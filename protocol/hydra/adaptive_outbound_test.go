package hydra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

func TestAdaptiveOutboundRegistryWiring(t *testing.T) {
	const tag = "registry-wired-outbound"
	opts := option.HydraOutboundOptions{Pubkey: encodeB64(make([]byte, 32)), Adaptive: &option.HydraAdaptiveOptions{ProofURL: "https://example.com/proof", ProofBytes: 1024, Candidates: []option.HydraAdaptiveCandidateOptions{{ID: "a", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}, Path: "/a"}}}}
	a, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, tag, opts, adaptiveOutboundDependencies{DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
		return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
	}})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	snap, ok := adaptive.SnapshotByTag(tag)
	if !ok {
		t.Fatal("adaptive outbound missing from registry after construction")
	}
	if snap.Closed || snap.Generation == 0 {
		t.Fatalf("fresh coordinator snapshot = %+v", snap)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := adaptive.SnapshotByTag(tag); ok {
		t.Fatal("adaptive outbound still registered after Close")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := adaptive.SnapshotByTag(tag); ok {
		t.Fatal("registry entry resurrected by repeated Close")
	}
}

func TestAdaptiveDistinctPaths(t *testing.T) {
	opts := option.HydraOutboundOptions{Pubkey: encodeB64(make([]byte, 32)), Adaptive: &option.HydraAdaptiveOptions{ProofURL: "https://example.com/proof", ProofBytes: 1024, Candidates: []option.HydraAdaptiveCandidateOptions{{ID: "a", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}, Path: "/a"}, {ID: "b", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}, Path: "/b"}}}}
	o, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "test", opts, adaptiveOutboundDependencies{DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
		return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer o.(*Outbound).Close()
}

func TestAdaptiveValidation(t *testing.T) {
	for _, name := range []string{"empty", "duplicate-id", "duplicate-endpoint", "server", "port", "proof", "bytes", "timing", "recovery-budget", "parent-detour", "candidate-detour"} {
		t.Run(name, func(t *testing.T) {
			opts := option.HydraOutboundOptions{Pubkey: encodeB64(make([]byte, 32)), Adaptive: &option.HydraAdaptiveOptions{Candidates: []option.HydraAdaptiveCandidateOptions{{ID: "a", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}}}, ProofURL: "https://example.com/proof", ProofBytes: 1024}}
			a := opts.Adaptive
			switch name {
			case "empty":
				a.Candidates = nil
			case "duplicate-id":
				v := a.Candidates[0]
				v.ServerPort = 444
				a.Candidates = append(a.Candidates, v)
			case "duplicate-endpoint":
				v := a.Candidates[0]
				v.ID = "b"
				a.Candidates = append(a.Candidates, v)
			case "server":
				a.Candidates[0].Server = "bad/server"
			case "port":
				a.Candidates[0].ServerPort = 0
			case "proof":
				a.ProofURL = "http://example.com"
			case "bytes":
				a.ProofBytes = 1023
			case "timing":
				a.Backoff = -1
			case "recovery-budget":
				// Default attempt 10s x 1 candidate exceeds the 5s floor.
				a.RecoveryBudget = badoption.Duration(5 * time.Second)
			case "parent-detour":
				opts.Detour = "active"
			case "candidate-detour":
				a.Candidates[0].Detour = "active"
			}
			if o, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "test", opts, adaptiveOutboundDependencies{DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
				return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
			}}); err == nil {
				o.(*Outbound).Close()
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestAdaptiveOutboundRust(t *testing.T) {
	addr, pk, _ := startRustServer(t)
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	go func() {
		for {
			c, e := blackhole.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 4096)
				for {
					if _, e := c.Read(b); e != nil {
						return
					}
				}
			}()
		}
	}()
	for _, valid := range []bool{true, false} {
		t.Run(strconv.FormatBool(valid), func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := r.URL.Query().Get("nonce")
				w.Header().Set("X-Hydra-Nonce", n)
				b := proofTestBody(n, 1024)
				if !valid {
					b[0] ^= 1
				}
				w.Write(b)
			}))
			defer origin.Close()
			candidate := func(id, addr string) option.HydraAdaptiveCandidateOptions {
				h, p, _ := net.SplitHostPort(addr)
				port, _ := strconv.Atoi(p)
				return option.HydraAdaptiveCandidateOptions{ID: id, ServerOptions: option.ServerOptions{Server: h, ServerPort: uint16(port)}}
			}
			opts := option.HydraOutboundOptions{Pubkey: encodeB64(pk[:]), Adaptive: &option.HydraAdaptiveOptions{Candidates: []option.HydraAdaptiveCandidateOptions{candidate("blackhole", blackhole.Addr().String()), candidate("good", addr)}, ProofURL: origin.URL, ProofBytes: 1024, AttemptTimeout: badoption.Duration(300 * time.Millisecond)}}
			roots := x509.NewCertPool()
			roots.AddCert(origin.Certificate())
			proofTLS := &tls.Config{RootCAs: roots}
			factoryCalls := 0
			a, e := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "test", opts, adaptiveOutboundDependencies{
				ProofTLS: proofTLS,
				DialerFactory: func(ctx context.Context, candidate option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
					factoryCalls++
					return dialer.New(ctx, candidate.DialerOptions, candidate.ServerIsDomain())
				},
			})
			if e != nil {
				t.Fatal(e)
			}
			o := a.(*Outbound)
			defer o.Close()
			if factoryCalls != 2 {
				t.Fatalf("factory calls = %d", factoryCalls)
			}
			// Mutating caller-owned TLS settings must not change the captured proof settings.
			proofTLS.RootCAs = x509.NewCertPool()
			roots.AddCert(origin.Certificate())
			if o.adaptiveSnapshot().Attempts != 0 {
				t.Fatal("construction dialed")
			}
			short, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			start := time.Now()
			if _, e = o.getTunnel(short); e == nil {
				t.Fatal("waiter should cancel")
			}
			if time.Since(start) > 200*time.Millisecond {
				t.Fatal("cancellation blocked")
			}
			ctx, stop := context.WithTimeout(t.Context(), 2*time.Second)
			defer stop()
			if !valid {
				if _, e = o.getTunnel(ctx); e == nil {
					t.Fatal("invalid proof promoted")
				}
				if o.adaptiveSnapshot().ActiveID != "" {
					t.Fatal("invalid active")
				}
				return
			}
			var wg sync.WaitGroup
			results := make(chan *Tunnel, 8)
			errs := make(chan error, 8)
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); tun, e := o.getTunnel(ctx); results <- tun; errs <- e }()
			}
			wg.Wait()
			close(results)
			close(errs)
			for e := range errs {
				if e != nil {
					t.Fatal(e)
				}
			}
			var first *Tunnel
			for tun := range results {
				if first == nil {
					first = tun
				}
				if first != tun {
					t.Fatal("different shared tunnel")
				}
			}
			if o.adaptiveSnapshot().ActiveID != "good" {
				t.Fatal("wrong candidate")
			}
			o.resetAdaptiveNetwork()
			if !first.IsDead() {
				t.Fatal("reset retained tunnel")
			}
		})
	}
}
