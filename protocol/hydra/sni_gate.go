package hydra

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Anti-salvo hardening (article rule: >3 handshakes to one SNI in a short
// window alongside a hosting ASN is a freeze signature).
//
// Two mechanisms live here:
//
//   - validateTLSFingerprint: the closed whitelist of uTLS ClientHello
//     fingerprints sing-box's utls layer understands (common/tls/utls_client.go
//     uTLSClientHelloID). An unknown name is a construction error — the axis
//     exists precisely to control the on-wire ClientHello, so a typo must
//     never silently fall back to plain TLS.
//
//   - sniGate: a per-HOST minimum spacing between handshake attempts inside
//     one adaptive outbound. The coordinator's epochs and prewarms can fire
//     several candidate handshakes to the same host in quick succession (the
//     coverage sweep re-arms every Backoff); every candidate dialer is wrapped
//     so handshakes to the SAME host are separated by spacing + uniform
//     0..spacing jitter (default 2000 ms base → 2-4 s effective). The jitter
//     reuses the coordinator's anti-synchronization idea (adaptive.jittered)
//     with a wider 1x spread: the point is to break the exact-ticker cadence,
//     not just desynchronize peers.

// uTLSFingerprints is the closed vocabulary accepted for
// tls_fingerprint. Mirror of common/tls uTLSClientHelloID's switch —
// keep the two in sync.
var uTLSFingerprints = map[string]bool{
	"chrome":                     true,
	"chrome_psk":                 true,
	"chrome_psk_shuffle":         true,
	"chrome_padding_psk_shuffle": true,
	"chrome_pq":                  true,
	"chrome_pq_psk":              true,
	"firefox":                    true,
	"edge":                       true,
	"safari":                     true,
	"360":                        true,
	"qq":                         true,
	"ios":                        true,
	"android":                    true,
	"random":                     true,
	"randomized":                 true,
}

func validateTLSFingerprint(name string) error {
	if name == "" {
		return nil
	}
	if !uTLSFingerprints[name] {
		return fmt.Errorf("hydra: unknown tls_fingerprint %q (known: chrome, firefox, edge, safari, ios, android, 360, qq, random, randomized, chrome_psk*)", name)
	}
	return nil
}

// DefaultHandshakeSpacingMs is the effective base spacing when the axis is
// unset: with the 0..base uniform jitter this lands in the 2-4 s band.
const DefaultHandshakeSpacingMs = 2000

// HandshakeSpacing bounds for the axis (option value clamps).
const (
	HandshakeSpacingMinMs = 100
	HandshakeSpacingMaxMs = 60000
)

// clampHandshakeSpacing maps the option axis onto the effective base spacing.
// 0 = default; out-of-band values clamp (never error — spacing is a safety
// floor, an over-large value only slows the sweep down).
// effectiveSpacing resolves the base spacing for one candidate. Loopback
// hosts bypass the gate entirely: there is no on-path observer on loopback,
// and every unit/integration target dials 127.0.0.1 — a floor there would
// only stall tests.
func effectiveSpacing(host string, v uint32) time.Duration {
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() || host == "localhost" {
		return 0
	}
	return clampHandshakeSpacing(v)
}

func clampHandshakeSpacing(v uint32) time.Duration {
	switch {
	case v == 0:
		return time.Duration(DefaultHandshakeSpacingMs) * time.Millisecond
	case v < HandshakeSpacingMinMs:
		return time.Duration(HandshakeSpacingMinMs) * time.Millisecond
	case v > HandshakeSpacingMaxMs:
		return time.Duration(HandshakeSpacingMaxMs) * time.Millisecond
	default:
		return time.Duration(v) * time.Millisecond
	}
}

// sniGate serializes handshake attempts per host with a jittered minimum
// spacing. Reservation-based: a granted wait reserves the slot immediately
// under the lock, so concurrent attempt workers queue instead of bursting.
type sniGate struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newSNIGate() *sniGate {
	return &sniGate{last: make(map[string]time.Time)}
}

// wait blocks until at least jitteredSpacing since the previous handshake to
// host started, then reserves the new slot. Cancelled ctx releases nothing
// (the reservation is the spacing budget — a cancelled caller still consumed
// the slot, which is the safe direction for an anti-salvo floor).
func (g *sniGate) wait(ctx context.Context, host string, spacing time.Duration) error {
	if spacing <= 0 {
		return nil
	}
	for {
		deadline := func() time.Time {
			g.mu.Lock()
			defer g.mu.Unlock()
			next := g.last[host].Add(spacing + time.Duration(rand.Int64N(int64(spacing)+1)))
			now := time.Now()
			if next.Before(now) {
				next = now
			}
			g.last[host] = next
			return next
		}()
		delay := time.Until(deadline)
		if delay <= 0 {
			return nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

// sniSpacingDialer wraps a candidate dialer with the shared per-host gate.
// Both the TCP dial (wss handshake) and the packet socket (rtc handshake)
// pass through the gate: both produce a server-visible handshake burst.
type sniSpacingDialer struct {
	N.Dialer
	gate    *sniGate
	host    string
	spacing time.Duration
}

func (d sniSpacingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := d.gate.wait(ctx, d.host, d.spacing); err != nil {
		return nil, err
	}
	return d.Dialer.DialContext(ctx, network, destination)
}

func (d sniSpacingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := d.gate.wait(ctx, d.host, d.spacing); err != nil {
		return nil, err
	}
	return d.Dialer.ListenPacket(ctx, destination)
}
