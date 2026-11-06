package hydra

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Integration: the REAL signed fixture from testdata is verified with the
// fixed cross-language seed's public key (same derivation as
// catalogue_test.go) and expanded into adaptive outbound candidates. Every
// assertion below runs against the shipped signed document, not against
// hand-built tables — except the ordering/fail-closed probes, which need
// catalogue shapes the single-recipe fixture cannot express (those docs are
// structurally valid but never produced by the real signer).
//
// Fixture times (must match testdata/catalogue_signed.json):
// issued_at=1735689600, expires_at=1893456000, seq=42.

const fixtureNow uint64 = 1800000000
const fixtureMinSeq uint64 = 42

// fixturePubkeyB64 is srv-main's pubkey as printed in the shipped fixture:
// base64 of bytes 0x01..0x20. Hardcoded here to pin the fixture against
// silent regeneration.
const fixturePubkeyB64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

func loadVerifiedFixture(t *testing.T) *Catalogue {
	t.Helper()
	payload, sig := loadFixture(t)
	cat, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), fixtureNow, fixtureMinSeq)
	if err != nil {
		t.Fatalf("verify shipped fixture: %v", err)
	}
	return cat
}

func TestCatalogueExpansionSignedFixture(t *testing.T) {
	cat := loadVerifiedFixture(t)
	cands, skips, err := CandidatesFromCatalogue(cat, "12345")
	if err != nil {
		t.Fatalf("expand asn 12345: %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("candidates = %d, want 1 (one wss recipe, one wss endpoint)", len(cands))
	}
	c := cands[0]
	if c.ID != "rec-fast" {
		t.Fatalf("candidate ID = %q, want rec-fast", c.ID)
	}
	if c.Server != "hy.example.net" || c.ServerPort != 443 {
		t.Fatalf("candidate server = %s:%d, want hy.example.net:443", c.Server, c.ServerPort)
	}
	if c.Path != "/hydra" {
		t.Fatalf("candidate path = %q, want /hydra", c.Path)
	}
	if c.TLS == nil {
		t.Fatal("candidate TLS must be non-nil (wss transport)")
	}
	if !c.TLS.Enabled {
		t.Fatal("candidate TLS.Enabled must be true")
	}
	if c.TLS.ServerName != "hy.example.net" {
		t.Fatalf("candidate TLS.ServerName = %q, want hy.example.net (endpoint SNI)", c.TLS.ServerName)
	}
	if c.TLS.Insecure {
		t.Fatal("candidate TLS.Insecure must NOT be set: TLS layer stays verification-capable")
	}
	if c.Detour != "" {
		t.Fatalf("candidate DialerOptions must be left zero, got Detour=%q", c.Detour)
	}
	// rtc material is counted and skipped, never expanded.
	if len(skips) == 0 {
		t.Fatal("skips must record the rtc endpoint the fixture carries")
	}
	rtcSkip := false
	for _, s := range skips {
		if strings.Contains(s, "rtc-not-wired") && strings.Contains(s, ":34443") && strings.Contains(s, "/hydra-rtc") {
			rtcSkip = true
		}
	}
	if !rtcSkip {
		t.Fatalf("skips = %v, want an rtc-not-wired entry for hy.example.net:34443/hydra-rtc", skips)
	}
}

func TestCatalogueExpansionUnknownASN(t *testing.T) {
	cat := loadVerifiedFixture(t)
	hinted, _, err := CandidatesFromCatalogue(cat, "12345")
	if err != nil {
		t.Fatalf("expand asn 12345: %v", err)
	}
	docOrder, _, err := CandidatesFromCatalogue(cat, "99999")
	if err != nil {
		t.Fatalf("expand unknown asn: %v", err)
	}
	if len(docOrder) != 1 || docOrder[0].ID != "rec-fast" {
		t.Fatalf("unknown asn must fall back to document order, got %+v", docOrder)
	}
	if docOrder[0].Server != hinted[0].Server || docOrder[0].ServerPort != hinted[0].ServerPort ||
		docOrder[0].Path != hinted[0].Path {
		t.Fatalf("unknown asn candidate differs from hinted one: %+v vs %+v", docOrder[0], hinted[0])
	}
	// asn == "" skips the hint phase entirely and must give the same result.
	empty, _, err := CandidatesFromCatalogue(cat, "")
	if err != nil || len(empty) != 1 || empty[0].ID != "rec-fast" {
		t.Fatalf("empty asn expansion = %+v err %v, want the document-order candidate", empty, err)
	}
}

func TestCatalogueExpansionRecipeMaxFrame(t *testing.T) {
	cat := loadVerifiedFixture(t)
	// The shipped fixture carries params mtu/mode but no max_frame.
	if v, ok := RecipeMaxFrame(cat, "rec-fast"); ok || v != 0 {
		t.Fatalf("RecipeMaxFrame(rec-fast) = (%d,%v), want (0,false): fixture has no max_frame", v, ok)
	}
	if v, ok := RecipeMaxFrame(cat, "ghost"); ok || v != 0 {
		t.Fatalf("RecipeMaxFrame(unknown recipe) = (%d,%v), want (0,false)", v, ok)
	}
	if v, ok := RecipeMaxFrame(nil, "rec-fast"); ok || v != 0 {
		t.Fatalf("RecipeMaxFrame(nil) = (%d,%v), want (0,false)", v, ok)
	}
	// Mapping boundaries on a hand-built recipe (loader guarantees the value
	// is a JSON number => float64 here).
	mk := func(v any) *Catalogue {
		return &Catalogue{
			Schema: 1, Seq: 1, IssuedAt: 1, ExpiresAt: 2,
			Servers: []CatalogueServer{{ID: "srv", Pubkey: b64ZeroPubkey(), Endpoints: []CatalogueEndpoint{{Transport: "wss", Host: "h", Port: 1, Path: "/"}}}},
			Recipes: []CatalogueRecipe{{ID: "rec", Server: "srv", Transport: "wss", Params: map[string]any{"max_frame": v}}},
		}
	}
	for name, tc := range map[string]struct {
		v    any
		want uint32
		ok   bool
	}{
		"low bound":   {float64(1024), 1024, true},
		"high bound":  {float64(65536), 65536, true},
		"below range": {float64(1023), 0, false},
		"above range": {float64(65537), 0, false},
		"fractional":  {1024.5, 0, false},
		"string":      {"2048", 0, false},
	} {
		if v, ok := RecipeMaxFrame(mk(tc.v), "rec"); ok != tc.ok || v != tc.want {
			t.Fatalf("max_frame %s: got (%d,%v), want (%d,%v)", name, v, ok, tc.want, tc.ok)
		}
	}
}

func TestCatalogueExpansionServerPubkey(t *testing.T) {
	cat := loadVerifiedFixture(t)
	pk, err := ServerPubkey(cat, "rec-fast")
	if err != nil {
		t.Fatalf("ServerPubkey(rec-fast): %v", err)
	}
	if len(pk) != ServerPubkeyLen {
		t.Fatalf("pubkey len = %d, want %d", len(pk), ServerPubkeyLen)
	}
	want, err := base64.StdEncoding.DecodeString(fixturePubkeyB64)
	if err != nil {
		t.Fatalf("decode fixture pubkey: %v", err)
	}
	if !bytes.Equal(pk, want) {
		t.Fatalf("pubkey = %x, want fixture bytes %x", pk, want)
	}
	if _, err := ServerPubkey(cat, "ghost"); err == nil {
		t.Fatal("unknown recipe must error")
	}
	if _, err := ServerPubkey(nil, "rec-fast"); err == nil {
		t.Fatal("nil catalogue must error")
	}
}

func TestCatalogueExpansionOrderHintsFirst(t *testing.T) {
	// Three recipes: rec-a (wss, srv-a), rec-b (rtc), rec-c (wss, srv-b).
	// Hints for 12345 name rec-c twice plus a ghost id. Expected order:
	// rec-c (hinted, deduped), rec-a (remaining document order); rec-b is
	// skipped as rtc-not-wired and the ghost hint is dropped (only existing
	// recipes are ordered; the loader rejects ghosts in signed documents).
	cat := &Catalogue{
		Schema: 1, Seq: 1, IssuedAt: 1, ExpiresAt: 2,
		Servers: []CatalogueServer{
			{ID: "srv-a", Pubkey: b64ZeroPubkey(), Endpoints: []CatalogueEndpoint{
				{Transport: "wss", Host: "a.example.net", Port: 443, Path: "/a", SNI: "a.example.net"},
			}},
			{ID: "srv-b", Pubkey: b64ZeroPubkey(), Endpoints: []CatalogueEndpoint{
				{Transport: "rtc", Host: "b.example.net", Port: 34443, Path: "/b-rtc"},
				{Transport: "wss", Host: "b.example.net", Port: 443, Path: "/b"},
			}},
		},
		Recipes: []CatalogueRecipe{
			{ID: "rec-a", Server: "srv-a", Transport: "wss"},
			{ID: "rec-b", Server: "srv-b", Transport: "rtc"},
			{ID: "rec-c", Server: "srv-b", Transport: "wss"},
		},
		Hints: map[string][]string{"12345": {"rec-c", "rec-c", "rec-ghost"}},
	}
	cands, skips, err := CandidatesFromCatalogue(cat, "12345")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(cands) != 2 {
		t.Fatalf("candidates = %d, want 2", len(cands))
	}
	if cands[0].ID != "rec-c" || cands[1].ID != "rec-a" {
		t.Fatalf("order = [%s %s], want [rec-c rec-a]: hints first, then document order", cands[0].ID, cands[1].ID)
	}
	if cands[1].Server != "a.example.net" || cands[0].Server != "b.example.net" {
		t.Fatalf("candidate server wiring wrong: %+v", cands)
	}
	recipeSkip, endpointSkip := false, false
	for _, s := range skips {
		if s == "recipe rec-b: rtc-not-wired" {
			recipeSkip = true
		}
		if strings.Contains(s, "rtc-not-wired") && strings.Contains(s, "srv-b") && strings.Contains(s, ":34443") {
			endpointSkip = true
		}
	}
	if !recipeSkip || !endpointSkip {
		t.Fatalf("skips = %v, want recipe rec-b rtc skip AND srv-b rtc endpoint skip", skips)
	}
	// Empty ASN: pure document order [rec-a, rec-c].
	doc, _, err := CandidatesFromCatalogue(cat, "")
	if err != nil || len(doc) != 2 || doc[0].ID != "rec-a" || doc[1].ID != "rec-c" {
		t.Fatalf("empty asn order = %+v err %v, want [rec-a rec-c]", doc, err)
	}
}

func TestCatalogueExpansionFailClosed(t *testing.T) {
	if _, _, err := CandidatesFromCatalogue(nil, "12345"); err == nil {
		t.Fatal("nil catalogue must error")
	}
	pub := b64ZeroPubkey()
	// Unknown server ref fails the whole expansion, naming the field.
	unknownSrv := &Catalogue{
		Schema: 1, Seq: 1, IssuedAt: 1, ExpiresAt: 2,
		Servers: []CatalogueServer{{ID: "srv-a", Pubkey: pub, Endpoints: []CatalogueEndpoint{
			{Transport: "wss", Host: "a.example.net", Port: 443, Path: "/a"},
		}}},
		Recipes: []CatalogueRecipe{{ID: "rec-x", Server: "srv-missing", Transport: "wss"}},
	}
	if _, _, err := CandidatesFromCatalogue(unknownSrv, ""); err == nil ||
		!strings.Contains(err.Error(), "unknown server ref") || !strings.Contains(err.Error(), "srv-missing") {
		t.Fatalf("unknown server ref: err = %v, want named failure", err)
	}
	// A wss recipe on a server without any wss endpoint fails closed.
	noWSS := &Catalogue{
		Schema: 1, Seq: 1, IssuedAt: 1, ExpiresAt: 2,
		Servers: []CatalogueServer{{ID: "srv-r", Pubkey: pub, Endpoints: []CatalogueEndpoint{
			{Transport: "rtc", Host: "r.example.net", Port: 34443, Path: "/r"},
		}}},
		Recipes: []CatalogueRecipe{{ID: "rec-w", Server: "srv-r", Transport: "wss"}},
	}
	if _, _, err := CandidatesFromCatalogue(noWSS, ""); err == nil || !strings.Contains(err.Error(), "no wss endpoint") {
		t.Fatalf("server without wss endpoint: err = %v, want fail-closed", err)
	}
	// A revoked recipe in a hand-built document is skipped, never expanded.
	revoked := &Catalogue{
		Schema: 1, Seq: 1, IssuedAt: 1, ExpiresAt: 2,
		Servers: []CatalogueServer{{ID: "srv-a", Pubkey: pub, Endpoints: []CatalogueEndpoint{
			{Transport: "wss", Host: "a.example.net", Port: 443, Path: "/a"},
		}}},
		Recipes:     []CatalogueRecipe{{ID: "rec-r", Server: "srv-a", Transport: "wss"}},
		Revocations: []string{"rec-r"},
	}
	cands, skips, err := CandidatesFromCatalogue(revoked, "")
	if err != nil {
		t.Fatalf("revoked recipe expansion: %v", err)
	}
	if len(cands) != 0 {
		t.Fatalf("revoked recipe must not expand, got %+v", cands)
	}
	found := false
	for _, s := range skips {
		if strings.Contains(s, "rec-r") && strings.Contains(s, "revoked") {
			found = true
		}
	}
	if !found {
		t.Fatalf("skips = %v, want revoked entry for rec-r", skips)
	}
}

func TestCatalogueExpansionSignatureBound(t *testing.T) {
	// The expansion consumes ONLY loader-verified documents. Flipping one
	// byte of the shipped fixture must break verification, so no candidate
	// can ever be derived from tampered material.
	payload, sig := loadFixture(t)
	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-1] ^= 0x01
	cat, err := LoadAndVerifyCatalogue(tampered, sig, fixedPub(t), fixtureNow, fixtureMinSeq)
	if err == nil {
		t.Fatal("tampered fixture must fail verification")
	}
	var ce *CatalogueError
	if !errors.As(err, &ce) || ce.Code != ErrCatalogueSigInvalid {
		t.Fatalf("tampered fixture err = %v, want sig_invalid", err)
	}
	if cat != nil {
		t.Fatalf("failed verification must yield nil catalogue, got %+v", cat)
	}
	// The rejected input cannot reach the expansion: nil is refused.
	if _, _, err := CandidatesFromCatalogue(cat, "12345"); err == nil {
		t.Fatal("nil catalogue (rejected input) must be refused by the expansion")
	}
}

// b64ZeroPubkey returns a structurally valid 32-byte pubkey in base64 for
// hand-built catalogues.
func b64ZeroPubkey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, ServerPubkeyLen))
}
