package hydra

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func TestCatalogueProductionOutboundRust(t *testing.T) {
	addr, pk, stderr, stop := startRustServerLogged(t)
	host, portText, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portText)
	cat := Catalogue{Schema: 1, Seq: 1, IssuedAt: 1, ExpiresAt: 1893456000,
		Servers: []CatalogueServer{{ID: "server", Pubkey: encodeB64(pk[:]), Endpoints: []CatalogueEndpoint{
			{Transport: "wss", Host: host, Port: uint16(port), Path: "/a"},
			{Transport: "wss", Host: host, Port: uint16(port), Path: "/b"},
			{Transport: "rtc", Host: host, Port: uint16(port), Path: "/rtc"},
		}}}, Recipes: []CatalogueRecipe{
			{ID: "web", Server: "server", Transport: "wss", Params: map[string]any{"max_frame": 2048}},
			{ID: "rtc", Server: "server", Transport: "rtc", Params: map[string]any{"max_frame": 4096}},
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
	if len(candidates) != 3 || len(skips) != 0 {
		t.Fatalf("signed expansion: candidates=%+v skips=%v; want two WSS and one RTC", candidates, skips)
	}
	if candidates[0].ID == candidates[1].ID || candidates[0].RecipeID != "web" || candidates[2].Transport != "rtc" || candidates[2].RecipeID != "rtc" {
		t.Fatalf("endpoint/recipe identity lost: %+v", candidates)
	}
	for _, candidate := range candidates {
		parts := strings.Split(candidate.ID, ":")
		if len(parts) != 3 || parts[0] != "catalogue" || parts[1] != base64.RawURLEncoding.EncodeToString([]byte(candidate.RecipeID)) || len(parts[2]) != 64 {
			t.Fatalf("candidate ID is not unambiguous and fully hashed: %q", candidate.ID)
		}
	}
	// Re-sign the adversarial recipe name that collided with the old mixed ID scheme.
	endpointBytes, err := json.Marshal(verified.Servers[0].Endpoints[0])
	if err != nil {
		t.Fatal(err)
	}
	collisionRecipe := fmt.Sprintf("web/%x", sha256.Sum256(endpointBytes))
	cat.Recipes = append(cat.Recipes, CatalogueRecipe{ID: collisionRecipe, Server: "server", Transport: "rtc"})
	cat.Servers[0].Endpoints[0], cat.Servers[0].Endpoints[1] = cat.Servers[0].Endpoints[1], cat.Servers[0].Endpoints[0]
	payload, err = json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	verified, err = LoadAndVerifyCatalogue(payload, ed25519.Sign(priv, payload), pub, fixtureNow, 1)
	if err != nil {
		t.Fatal(err)
	}
	reordered, _, err := CandidatesFromCatalogue(verified, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(reordered) != 4 || reordered[0].ID != candidates[1].ID || reordered[1].ID != candidates[0].ID || reordered[2].ID != candidates[2].ID {
		t.Fatalf("IDs changed on endpoint reorder: %+v", reordered)
	}
	seen := make(map[string]bool)
	for _, candidate := range reordered {
		if seen[candidate.ID] {
			t.Fatalf("candidate ID collision: %q", candidate.ID)
		}
		seen[candidate.ID] = true
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		w.Header().Set("X-Hydra-Nonce", nonce)
		_, _ = w.Write(proofTestBody(nonce, 1024))
	}))
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	// The Rust fixture speaks plain WS. Terminate the catalogue's TLS fronting
	// locally while retaining production adaptive selection, authentication and negotiation.
	for i := range candidates {
		if candidates[i].Transport == "wss" {
			candidates[i].TLS = nil
		}
	}
	// Aliases and inherited defaults must not create extra effective configurations.
	for _, inherited := range []bool{false, true} {
		first := candidates[0]
		alias := first
		alias.ID += "-alias"
		alias.RecipeID = "alias"
		if inherited {
			alias.Pubkey = ""
			alias.NegotiateMaxFrame = 0
			alias.RecipeID = ""
		}
		calls := 0
		duplicate, duplicateErr := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "catalogue-duplicate", option.HydraOutboundOptions{Pubkey: first.Pubkey, NegotiateMaxFrame: first.NegotiateMaxFrame, Adaptive: &option.HydraAdaptiveOptions{Candidates: []option.HydraAdaptiveCandidateOptions{first, alias}, ProofURL: origin.URL, ProofBytes: 1024}}, adaptiveOutboundDependencies{DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
			calls++
			return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
		}})
		if duplicateErr == nil {
			_ = duplicate.(*Outbound).Close()
			t.Fatalf("effective duplicate accepted (inherited=%v)", inherited)
		}
		if calls != 1 {
			t.Fatalf("duplicate built %d dialers, want 1", calls)
		}
	}
	// Different tuning or authenticated server identity remains distinct.
	for _, differentKey := range []bool{false, true} {
		first := candidates[0]
		other := first
		other.ID += "-distinct"
		other.RecipeID = "another-recipe"
		if differentKey {
			other.Pubkey = encodeB64(make([]byte, 32))
		} else {
			other.NegotiateMaxFrame = 4096
		}
		distinct, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "catalogue-distinct", option.HydraOutboundOptions{Adaptive: &option.HydraAdaptiveOptions{Candidates: []option.HydraAdaptiveCandidateOptions{first, other}, ProofURL: origin.URL, ProofBytes: 1024}}, adaptiveOutboundDependencies{DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
			return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
		}})
		if err != nil {
			t.Fatalf("different key/frame collapsed: %v", err)
		}
		_ = distinct.(*Outbound).Close()
	}
	out, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "catalogue-rust", option.HydraOutboundOptions{NegotiateMaxFrame: 8192, Adaptive: &option.HydraAdaptiveOptions{Candidates: candidates, ProofURL: origin.URL, ProofBytes: 1024}}, adaptiveOutboundDependencies{ProofTLS: &tls.Config{RootCAs: roots}, DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
		return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
	}})
	if err != nil {
		t.Fatal(err)
	}
	o := out.(*Outbound)
	defer o.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tunnel, err := o.getTunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.NegotiatedMaxFrame() != 2048 {
		t.Fatalf("production negotiation=%d, want signed recipe 2048, not parent 8192", tunnel.NegotiatedMaxFrame())
	}
	echoHost, echoPort := splitHostPort(t, startTCPEcho(t))
	session, err := tunnel.openSession(ctx, echoHost, echoPort)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, session, make([]byte, 40000))
	_ = session.Close()
	stop()
	data, offers, max := scanDispatch(stderr.String())
	if offers == 0 || data < 20 || max > 2048 {
		t.Fatalf("Rust dispatch offers=%d data=%d max=%d", offers, data, max)
	}
}
