package hydra

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	N "github.com/sagernet/sing/common/network"
)

func newAdaptiveOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HydraOutboundOptions) (adapter.Outbound, error) {
	return newAdaptiveOutboundWithDependencies(ctx, router, logger, tag, options, adaptiveOutboundDependencies{})
}

type adaptiveOutboundDependencies struct {
	ProofTLS      *tls.Config
	DialerFactory func(context.Context, option.HydraAdaptiveCandidateOptions) (N.Dialer, error)
}

func newAdaptiveOutboundWithDependencies(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HydraOutboundOptions, deps adaptiveOutboundDependencies) (adapter.Outbound, error) {
	var proofTLS *tls.Config
	if deps.ProofTLS != nil {
		proofTLS = deps.ProofTLS.Clone()
		if proofTLS.RootCAs != nil {
			proofTLS.RootCAs = proofTLS.RootCAs.Clone()
		}
		if proofTLS.ClientCAs != nil {
			proofTLS.ClientCAs = proofTLS.ClientCAs.Clone()
		}
	}
	factory := deps.DialerFactory
	if factory == nil {
		factory = func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
			return newAdaptivePhysicalDialer(ctx, options.Adaptive, v)
		}
	}
	a := options.Adaptive
	if a == nil {
		return nil, fmt.Errorf("hydra: adaptive options required")
	}
	if options.Detour != "" || len(a.Candidates) == 0 || len(a.Candidates) > 64 {
		return nil, fmt.Errorf("hydra: invalid adaptive candidates or parent detour")
	}
	u, err := url.Parse(a.ProofURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || a.ProofBytes < 1024 || a.ProofBytes > 1048576 {
		return nil, fmt.Errorf("hydra: invalid HTTPS proof target")
	}
	if u.Port() != "" {
		if _, err = net.LookupPort("tcp", u.Port()); err != nil {
			return nil, fmt.Errorf("hydra: invalid proof port")
		}
	}
	attempt, backoff, max := time.Duration(a.AttemptTimeout), time.Duration(a.Backoff), time.Duration(a.MaxBackoff)
	if attempt == 0 {
		attempt = 10 * time.Second
	}
	if backoff == 0 {
		backoff = time.Second
	}
	if max == 0 {
		max = 30 * time.Second
	}
	if attempt < 100*time.Millisecond || attempt > time.Minute || backoff < 10*time.Millisecond || backoff > time.Minute || max < backoff || max > 5*time.Minute {
		return nil, fmt.Errorf("hydra: invalid adaptive timing")
	}
	candidates := make([]adaptive.Candidate, 0, len(a.Candidates))
	built := make(map[string]*Outbound)
	endpoints := make(map[string]bool)
	for _, v := range a.Candidates {
		host := strings.ToLower(strings.TrimSuffix(v.Server, "."))
		identity := v
		identity.ID = ""
		identity.Server = host
		identity.Transport = normalizeTransport(identity.Transport)
		if identity.Transport != transportWSS && identity.Transport != transportRTC {
			return nil, fmt.Errorf("hydra: candidate %q: unknown transport %q", v.ID, v.Transport)
		}
		if identity.Path == "" {
			identity.Path = "/"
		} else if !strings.HasPrefix(identity.Path, "/") {
			identity.Path = "/" + identity.Path
		}
		encoded, marshalErr := json.Marshal(identity)
		if marshalErr != nil {
			return nil, marshalErr
		}
		endpoint := string(encoded)
		if strings.TrimSpace(v.ID) == "" || built[v.ID] != nil || endpoints[endpoint] || host == "" || strings.ContainsAny(host, " /\\\t\n?#@") || v.ServerPort == 0 || v.Detour != "" {
			return nil, fmt.Errorf("hydra: invalid candidate %q", v.ID)
		}
		if net.ParseIP(host) == nil {
			for _, label := range strings.Split(host, ".") {
				if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
					return nil, fmt.Errorf("hydra: invalid server")
				}
				for _, r := range label {
					if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
						return nil, fmt.Errorf("hydra: invalid server")
					}
				}
			}
		}
		tlsOptions := v.TLS
		if tlsOptions != nil {
			copy := *tlsOptions
			tlsOptions = &copy
		}
		base, e := factory(ctx, v)
		if e != nil {
			return nil, e
		}
		if base == nil {
			return nil, fmt.Errorf("hydra: nil candidate dialer")
		}
		child, e := newStaticOutbound(ctx, logger, tag, option.HydraOutboundOptions{ServerOptions: v.ServerOptions, DialerOptions: v.DialerOptions, Pubkey: options.Pubkey, Path: v.Path, TLS: tlsOptions, Transport: v.Transport, NegotiateMaxFrame: options.NegotiateMaxFrame}, base)
		if e != nil {
			return nil, e
		}
		built[v.ID] = child.(*Outbound)
		endpoints[endpoint] = true
		candidates = append(candidates, adaptive.Candidate{ID: v.ID})
	}
	// Each candidate owns its transport. No candidate is dialed until Acquire.
	o := &Outbound{Adapter: built[a.Candidates[0].ID].Adapter, logger: logger}
	proofURL, proofBytes := a.ProofURL, a.ProofBytes
	c, err := adaptive.New(ctx, adaptive.Config{Candidates: candidates, AttemptTimeout: attempt, Backoff: backoff, MaxBackoff: max,
		Connect: func(ctx context.Context, v adaptive.Candidate) (adaptive.Resource, error) {
			b := built[v.ID]
			if b.rtcTransport {
				return connectTunnelRTC(ctx, func(c context.Context) (net.PacketConn, error) {
					return b.dialer.ListenPacket(c, b.serverAddr)
				}, b.pubkey[:], b.serverAddr.AddrPort(), logger, b.negotiateMaxFrame)
			}
			t, err := connectTunnel(ctx, func(ctx context.Context) (net.Conn, error) {
				return b.dialer.DialContext(ctx, N.NetworkTCP, b.serverAddr)
			}, &b.requestURL, b.headers, b.pubkey[:], logger)
			if err != nil {
				return nil, err
			}
			return t, nil
		},
		Verify: func(ctx context.Context, _ adaptive.Candidate, r adaptive.Resource) error {
			return verifyTunnelProof(ctx, r.(*Tunnel), proofTarget{URL: proofURL, Bytes: proofBytes, TLS: proofTLS})
		},
	})
	if err != nil {
		return nil, err
	}
	o.adaptive = c
	adaptive.RegisterOutbound(tag, c.Snapshot)
	return o, nil
}

func (o *Outbound) adaptiveSnapshot() adaptive.Snapshot {
	o.mu.Lock()
	c := o.adaptive
	o.mu.Unlock()
	if c == nil {
		return adaptive.Snapshot{}
	}
	return c.Snapshot()
}
func (o *Outbound) resetAdaptiveNetwork() {
	o.mu.Lock()
	c := o.adaptive
	closed := o.isClosed
	o.mu.Unlock()
	if c != nil && !closed {
		c.ResetNetwork()
	}
}
