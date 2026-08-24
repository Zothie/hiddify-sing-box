package urltest

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

const (
	// DefaultThroughputURL is a plain static object served by a large CDN. It
	// must return a real body: the whole point is to move bytes, so any
	// /generate_204 style endpoint is useless here.
	DefaultThroughputURL = "https://speed.cloudflare.com/__down?bytes=131072"

	// DefaultThroughputBytes is how much we ask for. It is deliberately far
	// past the ~16-20 KB point where TSPU-style throttling stops forwarding a
	// flow, so a frozen path fails this probe while still passing a latency
	// probe. Bigger would detect more slowly-degrading cases but costs the user
	// real bandwidth on metered mobile links every cycle.
	DefaultThroughputBytes int64 = 128 * 1024

	// DefaultMinCarriedBytes is the evidence bar for "this path actually moves
	// data". Set above the freeze threshold so a connection that dies mid-body
	// cannot pass, but below the full request size so ordinary short reads,
	// CDN truncation, or a slightly small object do not cause false evictions.
	DefaultMinCarriedBytes int64 = 64 * 1024
)

// ThroughputResult is the verdict of one bulk probe.
type ThroughputResult struct {
	// CarriedBytes is body bytes actually read off the wire.
	CarriedBytes int64
	// KBps is CarriedBytes over the transfer duration.
	KBps uint32
	// FirstByteDelay is time to first body byte, in ms -- comparable to what
	// the ordinary latency probe reports.
	FirstByteDelay uint16
}

// URLTestThroughput pulls a sized object through detour and reports how much
// data actually arrived and how fast.
//
// WHY THIS EXISTS
// The ordinary URLTest issues an HTTP HEAD against a 204 endpoint. That proves
// a TCP connection opened and TLS completed -- and nothing more. The failure
// mode this code exists to catch is precisely one where all of that succeeds:
// the censor permits the handshake and then silently stops forwarding after
// roughly 16-20 KB. Such a node answers a latency probe instantly and scores as
// the healthiest in the group while carrying no user traffic at all.
//
// So this probe insists on evidence of transfer: it reads the body and counts
// bytes. A frozen flow stalls partway and returns a short count (or times out),
// which is a fact about data delivery rather than about reachability.
//
// COST
// This is expensive relative to a HEAD, and bulk transfers are also what arms
// the censor's per-flow penalty. Callers MUST NOT run this concurrently across
// outbounds or on every cycle; see the serialization and backoff in the
// monitoring package. A short read is reported as a result with err == nil so
// the caller can act on partial evidence rather than only on hard errors.
func URLTestThroughput(ctx context.Context, link string, wantBytes int64, detour N.Dialer) (result ThroughputResult, err error) {
	if detour == nil {
		return result, fmt.Errorf("urltest dialer is nil")
	}
	if link == "" {
		link = DefaultThroughputURL
	}
	if wantBytes <= 0 {
		wantBytes = DefaultThroughputBytes
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return result, err
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return result, err
	}
	defer instance.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return result, err
	}
	// Ask for exactly the window we care about. Servers that honour Range give
	// us a bounded transfer; those that ignore it just send more, and we stop
	// reading at wantBytes anyway.
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", wantBytes-1))
	// Identity encoding: a compressed body would let a few KB on the wire
	// decode into far more, which would defeat the byte-count evidence.
	req.Header.Set("Accept-Encoding", "identity")

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
			DisableCompression: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// No client Timeout: the caller's context governs the deadline, and we
		// want a stall to surface as a short read we can measure rather than as
		// an opaque transport error.
	}
	defer client.CloseIdleConnections()

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return result, fmt.Errorf("throughput probe: unexpected status %d", resp.StatusCode)
	}

	firstByte := time.Time{}
	buf := make([]byte, 32*1024)
	var carried int64
	for carried < wantBytes {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if firstByte.IsZero() {
				firstByte = time.Now()
			}
			carried += int64(n)
		}
		if readErr != nil {
			// io.EOF here is not necessarily success: if it arrives before
			// wantBytes the transfer was short, which is exactly the frozen
			// case. The byte count is the verdict, not the error value.
			if readErr != io.EOF {
				err = readErr
			}
			break
		}
		if ctx.Err() != nil {
			err = ctx.Err()
			break
		}
	}

	elapsed := time.Since(start)
	result.CarriedBytes = carried
	if !firstByte.IsZero() {
		ttfb := firstByte.Sub(start).Milliseconds()
		switch {
		case ttfb < 0:
			result.FirstByteDelay = 0
		case ttfb > 65534:
			// Stay below TimeoutDelay (65535) so a slow-but-alive node is never
			// mistaken for a timed-out one.
			result.FirstByteDelay = 65534
		default:
			result.FirstByteDelay = uint16(ttfb)
		}
	}
	if carried > 0 && elapsed > 0 {
		kbps := float64(carried) / 1024 / elapsed.Seconds()
		if kbps > float64(^uint32(0)) {
			result.KBps = ^uint32(0)
		} else {
			result.KBps = uint32(kbps)
		}
	}

	// A stall that produced a partial body is a successful measurement of a
	// broken path, so report it as data (err stays nil) and let the caller
	// apply its own minimum-bytes policy.
	if err != nil && carried > 0 {
		err = nil
	}
	return result, err
}
