package hydra

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

// Audit G2 live path: a signed catalogue is verified, expanded with the REAL
// expansion, and swapped into a LIVE adaptive outbound. The outbound's
// coordinator then sweeps the swapped set against a real stalling TCP
// listener (accepts, never answers the hydra handshake) so attempts are
// bounded by AttemptTimeout and visible in PerCandidate.

// startStallListener accepts TCP connections forever and never writes, so a
// hydra handshake attempt hangs until its attempt timeout.
func startStallListener(t *testing.T) (host, port string, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				<-done
				_ = conn.Close()
			}()
		}
	}()
	h, p, _ := net.SplitHostPort(l.Addr().String())
	return h, p, func() { close(done); _ = l.Close() }
}

// swapTestCatalogue signs and verifies a catalogue with one server (relay
// pubkey) hosting count wss endpoints on host:port.
func swapTestCatalogue(t *testing.T, relayPub []byte, host string, port uint16, count int, seq uint64) *Catalogue {
	t.Helper()
	eps := make([]CatalogueEndpoint, 0, count)
	for i := range count {
		eps = append(eps, CatalogueEndpoint{Transport: "wss", Host: host, Port: port, Path: "/cat" + string(rune('a'+i))})
	}
	cat := Catalogue{Schema: 1, Seq: seq, IssuedAt: 1, ExpiresAt: 1893456000,
		Servers: []CatalogueServer{{ID: "relay", Pubkey: encodeB64(relayPub), Endpoints: eps}},
		Recipes: []CatalogueRecipe{{ID: "web", Server: "relay", Transport: "wss"}}}
	payload, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := LoadAndVerifyCatalogue(payload, ed25519.Sign(fixedPriv(t), payload), fixedPub(t), fixtureNow, 1)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func swapTestOutbound(t *testing.T, tag, relayPubB64, host string, port uint16, asn string) *Outbound {
	t.Helper()
	statics := []option.HydraAdaptiveCandidateOptions{
		{ID: "static-1", Pubkey: relayPubB64, Transport: "wss", ServerOptions: option.ServerOptions{Server: host, ServerPort: port}, Path: "/static1"},
		{ID: "static-2", Pubkey: relayPubB64, Transport: "wss", ServerOptions: option.ServerOptions{Server: host, ServerPort: port}, Path: "/static2"},
	}
	// The standard dialer factory (the pattern of the existing integration
	// tests): the production physical factory requires a pinned interface,
	// which a loopback test must not need.
	out, err := BuildAdaptiveOutboundWithDeps(t.Context(), nil, tag, option.HydraOutboundOptions{
		Pubkey:            relayPubB64,
		NegotiateMaxFrame: 2048,
		Adaptive: &option.HydraAdaptiveOptions{
			Candidates:     statics,
			ProofURL:       "https://proof.invalid/probe",
			ProofBytes:     1024,
			AttemptTimeout: badoption.Duration(300 * time.Millisecond),
			Backoff:        badoption.Duration(10 * time.Millisecond),
			MaxBackoff:     badoption.Duration(50 * time.Millisecond),
			CatalogueASN:   asn,
		},
	}, OutboundDeps{DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
		return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
	}})
	if err != nil {
		t.Fatal(err)
	}
	return out.(*Outbound)
}

func waitForSwap(t *testing.T, o *Outbound, wantCount int, wantSwapGen uint64, wantID string) adaptive.Snapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var snap adaptive.Snapshot
	for time.Now().Before(deadline) {
		snap = o.adaptiveSnapshot()
		if snap.CandidateCount == wantCount && snap.SwapGeneration == wantSwapGen && (wantID == "" || snap.PerCandidate[wantID] > 0) {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("swap not observed: count=%d swaps=%d per=%v", snap.CandidateCount, snap.SwapGeneration, snap.PerCandidate)
	return snap
}

func TestCatalogueHotSwapLiveOutbound(t *testing.T) {
	h, p, stop := startStallListener(t)
	defer stop()
	port64, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(port64)
	relayPriv := ed25519.NewKeyFromSeed(make([]byte, 32))
	relayPub := relayPriv.Public().(ed25519.PublicKey) // 32 bytes of key material for the relay binding
	relayPubB64 := encodeB64(relayPub)

	o := swapTestOutbound(t, "swap-live", relayPubB64, h, port, "12345")
	defer o.Close()
	// The coordinator's sweep loop starts on the first Acquire; drive it for
	// the whole test. Against the stall listener every attempt fails, which
	// is exactly what makes attempts visible in PerCandidate.
	sweepCtx, cancelSweep := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancelSweep()
	go func() { _, _ = o.getTunnel(sweepCtx) }()

	targets := CatalogueSwapTargets()
	if len(targets) != 1 {
		t.Fatalf("targets: %+v", targets)
	}
	tg := targets[0]
	if tg.Tag != "swap-live" || tg.Pubkey != relayPubB64 || tg.ASN != "12345" || tg.AttemptTimeout != 300*time.Millisecond || tg.Budget != 30*time.Second {
		t.Fatalf("target mismatch: %+v", tg)
	}
	if _, ok := adaptive.SnapshotByTag("swap-live"); !ok {
		t.Fatal("adaptive registry lost the tag")
	}

	verified := swapTestCatalogue(t, relayPub, h, port, 3, 9)
	expanded, skips, err := ExpandCatalogueCandidates(verified, "12345", 300*time.Millisecond, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded) != 3 || len(skips) != 0 {
		t.Fatalf("expansion: %d candidates, skips %v", len(expanded), skips)
	}
	if err := SwapCatalogueCandidates("swap-live", expanded); err != nil {
		t.Fatal(err)
	}
	snap := waitForSwap(t, o, 3, 1, expanded[0].ID)
	if snap.ActiveID != "" {
		// No tunnel can complete against the stall listener; an active id
		// would mean a fake verify sneaked in.
		t.Fatalf("nothing must promote against a stall listener: %q", snap.ActiveID)
	}
	// The sweep is sequential with AttemptTimeout-bounded attempts; wait
	// until EVERY swapped candidate has been attempted at least once.
	deadline := time.Now().Add(5 * time.Second)
	for {
		snap = o.adaptiveSnapshot()
		all := true
		for _, cand := range expanded {
			if snap.PerCandidate[cand.ID] == 0 {
				all = false
				break
			}
		}
		if all {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("swapped candidates not all attempted: %v", snap.PerCandidate)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Over-budget set rejected at the commit point (G5): 200 candidates x
	// 300ms = 60s > the 30s default budget. The budget gate fires before
	// any dialer is built.
	flood := make([]option.HydraAdaptiveCandidateOptions, 200)
	for i := range flood {
		flood[i] = option.HydraAdaptiveCandidateOptions{ID: "flood" + strconv.Itoa(i), Pubkey: relayPubB64, Transport: "wss", ServerOptions: option.ServerOptions{Server: h, ServerPort: port}, Path: "/f"}
	}
	if err := SwapCatalogueCandidates("swap-live", flood); err == nil {
		t.Fatal("over-budget swap must be rejected")
	}
	snap = o.adaptiveSnapshot()
	if snap.CandidateCount != 3 || snap.SwapGeneration != 1 {
		t.Fatalf("rejected swap mutated state: %+v", snap)
	}

	// Swap back to a static-shaped set (surviving ids reuse pooled children).
	statics := []option.HydraAdaptiveCandidateOptions{
		{ID: "static-1", Pubkey: relayPubB64, Transport: "wss", ServerOptions: option.ServerOptions{Server: h, ServerPort: port}, Path: "/static1"},
		{ID: "static-3", Pubkey: relayPubB64, Transport: "wss", ServerOptions: option.ServerOptions{Server: h, ServerPort: port}, Path: "/static3"},
	}
	if err := SwapCatalogueCandidates("swap-live", statics); err != nil {
		t.Fatal(err)
	}
	waitForSwap(t, o, 2, 2, "static-3")

	// Closed outbound: lazy unregister + explicit error.
	_ = o.Close()
	if err := SwapCatalogueCandidates("swap-live", expanded); err == nil {
		t.Fatal("swap against a closed outbound must fail")
	}
	if targets := CatalogueSwapTargets(); len(targets) != 0 {
		t.Fatalf("closed outbound must unregister lazily: %+v", targets)
	}
}
