package hydra

// REAL end-to-end proof of the tuning-axis sweep (TUNING.md wave 1) against
// the Rust hydra-server: a signed catalogue carries THREE variants of the
// SAME endpoint differing only in (a) ClientHello frag ranges + split delay,
// (b) disorder + pad_buckets, (c) max_frame. The test asserts the three
// variants expand as three DISTINCT candidates, the adaptive coordinator
// tries them as three distinct effective configurations (fair rotation
// across tunnel losses, UniqueCandidatesTried), every working variant
// completes a real handshake + useful-byte proof + data transfer, and an
// unknown recipe param still produces the explicit skip entry.
//
// Skipped when the hydra-server binary is absent (HYDRA_SERVER_BIN).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func TestAdaptiveAxesCandidatesRust(t *testing.T) {
	addr, pk, _, stop := startRustServerLogged(t)
	host, portText, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portText)

	// Proof origin: local TLS server answering the bounded GET; the tunnel
	// must fetch it THROUGH the verified session (useful-byte proof).
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		w.Header().Set("X-Hydra-Nonce", nonce)
		_, _ = w.Write(proofTestBody(nonce, 1024))
	}))
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())

	// Same endpoint (host:port/path), three axis-only variants.
	cat := Catalogue{Schema: 1, Seq: 1, IssuedAt: 1, ExpiresAt: 1893456000,
		Servers: []CatalogueServer{{ID: "server", Pubkey: encodeB64(pk[:]), Endpoints: []CatalogueEndpoint{
			{Transport: "wss", Host: host, Port: uint16(port), Path: "/axes"},
		}}}, Recipes: []CatalogueRecipe{
			{ID: "rec-frag", Server: "server", Transport: "wss", Params: map[string]any{
				"frag_first_min": float64(16), "frag_first_max": float64(48),
				"frag_rest_min": float64(24), "frag_rest_max": float64(64),
				"split_delay_ms": float64(2),
			}},
			{ID: "rec-disorder", Server: "server", Transport: "wss", Params: map[string]any{
				"disorder": float64(1), "disorder_delay_ms": float64(10),
				"pad_buckets": "512,2048,65536", "max_pad": float64(48),
			}},
			{ID: "rec-frame", Server: "server", Transport: "wss", Params: map[string]any{
				"max_frame": float64(2048),
			}},
			// Unknown param: must produce the explicit skip, never a candidate.
			{ID: "rec-unknown", Server: "server", Transport: "wss", Params: map[string]any{
				"quantum_flux": float64(1),
			}},
		}}
	payload, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := LoadAndVerifyCatalogue(payload, ed25519.Sign(priv, payload), pub, fixtureNow, 1)
	if err != nil {
		t.Fatal(err)
	}
	candidates, skips, err := CandidatesFromCatalogue(verified, "")
	if err != nil {
		t.Fatal(err)
	}
	// Three axis variants expand; the unknown param is an explicit skip.
	if len(candidates) != 3 || len(skips) != 1 || !strings.Contains(skips[0], "rec-unknown") || !strings.Contains(skips[0], "unsupported-param-quantum_flux") {
		t.Fatalf("expansion: candidates=%d skips=%v err=%v; want 3 variants + explicit unknown-param skip", len(candidates), skips, err)
	}
	// Axis values really flowed into the candidates.
	if candidates[0].FragFirstMin != 16 || candidates[0].FragSplitDelayMs != 2 {
		t.Fatalf("frag variant lost its axes: %+v", candidates[0])
	}
	if !candidates[1].Disorder || len(candidates[1].PadBuckets) != 3 || candidates[1].MaxPad != 48 {
		t.Fatalf("disorder/pad variant lost its axes: %+v", candidates[1])
	}
	if candidates[2].NegotiateMaxFrame != 2048 {
		t.Fatalf("max_frame variant lost its axis: %+v", candidates[2])
	}
	// Axis-only variants are distinct effective configurations: strip IDs and
	// the marshalled identities must all differ.
	seenID := make(map[string]string, len(candidates))
	for _, c := range candidates {
		id := c.ID
		c.ID, c.RecipeID = "", ""
		encoded, merr := json.Marshal(c)
		if merr != nil {
			t.Fatal(merr)
		}
		if prev, dup := seenID[string(encoded)]; dup {
			t.Fatalf("axis variants %s and %s collapsed into one effective config", prev, id)
		}
		seenID[string(encoded)] = id
	}
	// The Rust fixture speaks plain WS: terminate the catalogue's TLS fronting
	// locally while keeping production adaptive selection, authentication and
	// the pubkey-bound CONFIRM.
	for i := range candidates {
		candidates[i].TLS = nil
	}

	o, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "axes-rust", option.HydraOutboundOptions{Adaptive: &option.HydraAdaptiveOptions{Candidates: candidates, ProofURL: origin.URL, ProofBytes: 1024}}, adaptiveOutboundDependencies{ProofTLS: &tls.Config{RootCAs: roots}, DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
		return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
	}})
	if err != nil {
		t.Fatal(err)
	}
	ob := o.(*Outbound)
	defer ob.Close()

	echoHost, echoPort := splitHostPort(t, startTCPEcho(t))
	// Fair rotation: each tunnel loss moves the coordinator to the next
	// candidate, so all three axis variants are exercised as distinct configs
	// and every working variant completes handshake + proof + data transfer.
	activeIDs := make(map[string]bool, len(candidates))
	for want := 1; want <= len(candidates); want++ {
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		tunnel, err := ob.getTunnel(ctx)
		if err != nil {
			t.Fatalf("acquire candidate %d: %v", want, err)
		}
		session, err := tunnel.openSession(ctx, echoHost, echoPort)
		if err != nil {
			t.Fatalf("open on candidate %d: %v", want, err)
		}
		roundtrip(t, session, make([]byte, 40000))
		_ = session.Close()
		snap := ob.adaptiveSnapshot()
		if snap.UniqueCandidatesTried != uint64(want) {
			t.Fatalf("UniqueCandidatesTried = %d, want %d (each axis variant must be tried as a distinct config)", snap.UniqueCandidatesTried, want)
		}
		if snap.ActiveID == "" {
			t.Fatalf("no active candidate after acquire %d", want)
		}
		activeIDs[snap.ActiveID] = true
		_ = tunnel.Close()
		cancel()
	}
	if len(activeIDs) != len(candidates) {
		t.Fatalf("rotation touched %v, want all %d axis variants", activeIDs, len(candidates))
	}
	snap := ob.adaptiveSnapshot()
	if snap.Attempts < uint64(len(candidates)) {
		t.Fatalf("attempts = %d, want >= %d", snap.Attempts, len(candidates))
	}
	_ = stop
}
