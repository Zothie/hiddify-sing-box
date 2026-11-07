package hydra

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
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
	if err != nil || len(cands) != 0 || len(skips) != 3 {
		t.Fatalf("unsupported fixture axes must be reported: candidates=%v skips=%v err=%v", cands, skips, err)
	}
}

func checkSupportedFixtureExpansion(t *testing.T) {
	cat := loadVerifiedFixture(t)
	cat.Recipes[0].Params = nil
	cat.Recipes[0].Requires = nil
	cands, skips, err := CandidatesFromCatalogue(cat, "12345")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Fatalf("candidates = %d, want 1 (one wss recipe, one wss endpoint)", len(cands))
	}
	c := cands[0]
	if c.RecipeID != "rec-fast" {
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
	// Incompatible endpoints must not expand or masquerade as unsupported RTC.
	if len(skips) != 0 {
		t.Fatalf("unexpected skips: %v", skips)
	}
}

func TestCatalogueExpansionUnknownASN(t *testing.T) {
	checkSupportedFixtureExpansion(t)
	cat := loadVerifiedFixture(t)
	cat.Recipes[0].Params = nil
	cat.Recipes[0].Requires = nil
	hinted, _, err := CandidatesFromCatalogue(cat, "12345")
	if err != nil {
		t.Fatalf("expand asn 12345: %v", err)
	}
	docOrder, _, err := CandidatesFromCatalogue(cat, "99999")
	if err != nil {
		t.Fatalf("expand unknown asn: %v", err)
	}
	if len(docOrder) != 1 || docOrder[0].RecipeID != "rec-fast" {
		t.Fatalf("unknown asn must fall back to document order, got %+v", docOrder)
	}
	if docOrder[0].Server != hinted[0].Server || docOrder[0].ServerPort != hinted[0].ServerPort ||
		docOrder[0].Path != hinted[0].Path {
		t.Fatalf("unknown asn candidate differs from hinted one: %+v vs %+v", docOrder[0], hinted[0])
	}
	// asn == "" skips the hint phase entirely and must give the same result.
	empty, _, err := CandidatesFromCatalogue(cat, "")
	if err != nil || len(empty) != 1 || empty[0].RecipeID != "rec-fast" {
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
	if len(cands) != 3 {
		t.Fatalf("candidates = %d, want 3", len(cands))
	}
	if cands[0].RecipeID != "rec-c" || cands[1].RecipeID != "rec-a" {
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
	if recipeSkip || endpointSkip || len(skips) != 0 || cands[2].RecipeID != "rec-b" || cands[2].Transport != "rtc" {
		t.Fatalf("RTC expansion missing: candidates=%v skips=%v", cands, skips)
	}
	// Empty ASN: pure document order [rec-a, rec-c].
	doc, _, err := CandidatesFromCatalogue(cat, "")
	if err != nil || len(doc) != 3 || doc[0].RecipeID != "rec-a" || doc[1].RecipeID != "rec-b" || doc[2].RecipeID != "rec-c" {
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

// axisCatalogue builds a one-server, one-wss-endpoint catalogue whose single
// recipe carries the given params.
func axisCatalogue(params map[string]any) *Catalogue {
	return &Catalogue{
		Schema: 1, Seq: 1, IssuedAt: 1, ExpiresAt: 2,
		Servers: []CatalogueServer{{ID: "srv", Pubkey: b64ZeroPubkey(), Endpoints: []CatalogueEndpoint{
			{Transport: "wss", Host: "a.example.net", Port: 443, Path: "/a"},
		}}},
		Recipes: []CatalogueRecipe{{ID: "rec", Server: "srv", Transport: "wss", Params: params}},
	}
}

func TestCatalogueExpansionAxisParams(t *testing.T) {
	cands, skips, err := CandidatesFromCatalogue(axisCatalogue(map[string]any{
		"frag_first_min": float64(4), "frag_first_max": float64(80), // 80 clamps to 64
		"frag_rest_min": float64(10), "frag_rest_max": float64(120), // 120 clamps to 96
		"split_delay_ms": float64(500),                            // clamps to 50
		"disorder":       "true", "disorder_delay_ms": float64(0), // 0 = default
		"pad_buckets":     "512, 2048,65536",
		"max_pad":         float64(999),  // clamps to 64
		"big_pad_max":     float64(8192), // clamps to 4096
		"rtc_chunk":       float64(200),  // clamps to 256
		"rtc_window":      float64(2048), // clamps to 1024
		"rto_min":         float64(300),
		"rto_max":         float64(20000), // clamps to 10000
		"buffer_cap":      float64(64),    // clamps to 128
		"keepalive_every": float64(9000),
		"tls_fragment":    float64(1),
		"tls_min_version": "1.2",
		"tls_max_version": "1.3",
		"tls_alpn":        "h2, http/1.1",
		"max_frame":       float64(4096),
	}), "")
	if err != nil {
		t.Fatalf("axis expansion: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("unexpected skips: %v", skips)
	}
	if len(cands) != 1 {
		t.Fatalf("candidates = %d, want 1", len(cands))
	}
	c := cands[0]
	if c.FragFirstMin != 4 || c.FragFirstMax != 64 {
		t.Fatalf("frag first axis = %d..%d, want 4..64 (clamped)", c.FragFirstMin, c.FragFirstMax)
	}
	if c.FragRestMin != 10 || c.FragRestMax != 96 {
		t.Fatalf("frag rest axis = %d..%d, want 10..96 (clamped)", c.FragRestMin, c.FragRestMax)
	}
	if c.FragSplitDelayMs != 50 {
		t.Fatalf("split delay = %d, want 50 (clamped)", c.FragSplitDelayMs)
	}
	if !c.Disorder || c.DisorderDelayMs != 0 {
		t.Fatalf("disorder axis = %v/%d, want true/0(default)", c.Disorder, c.DisorderDelayMs)
	}
	if len(c.PadBuckets) != 3 || c.PadBuckets[0] != 512 || c.PadBuckets[1] != 2048 || c.PadBuckets[2] != 65536 {
		t.Fatalf("pad buckets = %v, want [512 2048 65536]", c.PadBuckets)
	}
	if c.MaxPad != 64 || c.BigPadMax != 4096 {
		t.Fatalf("pad caps = %d/%d, want 64/4096 (clamped)", c.MaxPad, c.BigPadMax)
	}
	if c.RTCChunk != 256 || c.RTCWindow != 1024 {
		t.Fatalf("rtc channel = %d/%d, want 256/1024 (clamped)", c.RTCChunk, c.RTCWindow)
	}
	if c.RTORtoMinMs != 300 || c.RTORtoMaxMs != 10000 || c.RTCBufferCap != 128 || c.RTCKeepaliveEveryMs != 9000 {
		t.Fatalf("rtc survivability axes = %d/%d/%d/%d, want 300/10000/128/9000", c.RTORtoMinMs, c.RTORtoMaxMs, c.RTCBufferCap, c.RTCKeepaliveEveryMs)
	}
	if !c.TLSFragment || c.TLSMinVersion != "1.2" || c.TLSMaxVersion != "1.3" {
		t.Fatalf("tls surface axes = %v/%q/%q, want true/1.2/1.3", c.TLSFragment, c.TLSMinVersion, c.TLSMaxVersion)
	}
	if len(c.TLSALPN) != 2 || c.TLSALPN[0] != "h2" || c.TLSALPN[1] != "http/1.1" {
		t.Fatalf("tls alpn = %v, want [h2 http/1.1]", c.TLSALPN)
	}
	if c.NegotiateMaxFrame != 4096 {
		t.Fatalf("max frame = %d, want 4096", c.NegotiateMaxFrame)
	}
	// Boolean disorder also accepts a numeric 1/0 form.
	numFlag, _, err := CandidatesFromCatalogue(axisCatalogue(map[string]any{"disorder": float64(1), "tls_fragment": float64(0)}), "")
	if err != nil || len(numFlag) != 1 || !numFlag[0].Disorder || numFlag[0].TLSFragment {
		t.Fatalf("numeric boolean flags = %+v err %v, want disorder=true tls_fragment=false", numFlag, err)
	}
}

func TestCatalogueExpansionAxisFailClosed(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"fractional frag":     {"frag_first_min": 4.5},
		"negative frag":       {"frag_first_min": float64(-1)},
		"string frag":         {"frag_first_min": "16"},
		"descending buckets":  {"pad_buckets": "1024,512"},
		"dup buckets":         {"pad_buckets": "512,512"},
		"low bucket member":   {"pad_buckets": "128,512"},
		"high bucket member":  {"pad_buckets": "512,131072"},
		"nine buckets":        {"pad_buckets": "256,512,1024,2048,4096,8192,16384,32768,65536"},
		"array buckets":       {"pad_buckets": []any{float64(512)}},
		"bad disorder flag":   {"disorder": "maybe"},
		"numeric tls version": {"tls_min_version": float64(1.2)},
		"bad max_pad":         {"max_pad": "x"},
	} {
		_, _, err := CandidatesFromCatalogue(axisCatalogue(params), "")
		if err == nil {
			t.Fatalf("%s: expansion must fail closed", name)
		}
	}
}

func TestCatalogueExpansionAxisUnknownParamSkipped(t *testing.T) {
	cands, skips, err := CandidatesFromCatalogue(axisCatalogue(map[string]any{
		"frag_first_min": float64(16),
		"quantum_flux":   float64(1),
	}), "")
	if err != nil {
		t.Fatalf("unknown param expansion: %v", err)
	}
	if len(cands) != 0 {
		t.Fatalf("recipe with unknown param must not expand, got %+v", cands)
	}
	found := false
	for _, s := range skips {
		if strings.Contains(s, "rec") && strings.Contains(s, "unsupported-param-quantum_flux") {
			found = true
		}
	}
	if !found {
		t.Fatalf("skips = %v, want unsupported-param-quantum_flux entry", skips)
	}
}

func TestCatalogueExpansionAxisIdentityDistinct(t *testing.T) {
	// Two recipes on the SAME endpoint differing only in one axis expand as
	// two distinct candidates (different identity hashes); the ID prefix
	// still names the recipe. Two recipes with IDENTICAL params produce
	// identical identity hashes — the effective-duplicate guard.
	base := map[string]any{"frag_first_min": float64(16)}
	varied := map[string]any{"frag_first_min": float64(32)}
	cat := axisCatalogue(nil)
	cat.Recipes = []CatalogueRecipe{
		{ID: "rec-a", Server: "srv", Transport: "wss", Params: base},
		{ID: "rec-b", Server: "srv", Transport: "wss", Params: varied},
	}
	cands, _, err := CandidatesFromCatalogue(cat, "")
	if err != nil || len(cands) != 2 {
		t.Fatalf("two axis variants = %+v err %v, want 2 candidates", cands, err)
	}
	if cands[0].ID == cands[1].ID {
		t.Fatal("variants differing only in one axis must have distinct IDs")
	}
	if cands[0].FragFirstMin != 16 || cands[1].FragFirstMin != 32 {
		t.Fatalf("axis values lost: %+v", cands)
	}
	// The catalogue ID's hash part covers the ENDPOINT (host/port/path/sni)
	// only — identical here by design. Axis distinctness lives in the
	// ADAPTIVE effective-options identity (the candidate struct JSON), which
	// the adaptive build deduplicates on; assert that the axis fields the
	// identity JSON will marshal really differ.
	identityOf := func(c option.HydraAdaptiveCandidateOptions) string {
		c.ID, c.RecipeID = "", ""
		encoded, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal identity: %v", err)
		}
		return string(encoded)
	}
	if identityOf(cands[0]) == identityOf(cands[1]) {
		t.Fatal("axis-only variants must marshal to different effective identities")
	}
	// Identical params on one endpoint: same identity hash — the adaptive
	// duplicate guard collapses them (covered by the integration suite).
	same := axisCatalogue(nil)
	same.Recipes = []CatalogueRecipe{
		{ID: "rec-a", Server: "srv", Transport: "wss", Params: base},
		{ID: "rec-b", Server: "srv", Transport: "wss", Params: map[string]any{"frag_first_min": float64(16)}},
	}
	dups, _, err := CandidatesFromCatalogue(same, "")
	if err != nil || len(dups) != 2 {
		t.Fatalf("identical-param recipes = %+v err %v, want 2 catalogue entries", dups, err)
	}
	if identityOf(dups[0]) != identityOf(dups[1]) {
		t.Fatal("identical params must marshal to the same effective identity")
	}
}

func TestAxesResolveAndIdentityCollapse(t *testing.T) {
	tuned := option.HydraAdaptiveCandidateOptions{FragFirstMin: 16, FragFirstMax: 48, PadBuckets: []uint32{512, 2048}, RTCChunk: 900, RTCWindow: 64, RTORtoMinMs: 120, RTORtoMaxMs: 4000, RTCBufferCap: 256, RTCKeepaliveEveryMs: 3000, MaxPad: 32, BigPadMax: 1024, TLSMinVersion: "1.2", TLSALPN: []string{"h2"}}
	alias := option.HydraAdaptiveCandidateOptions{}
	merged, axes, err := axesOrDefault(alias, tuned, nil)
	if err != nil {
		t.Fatalf("axesOrDefault: %v", err)
	}
	if merged.FragFirstMin != 16 || merged.RTCChunk != 900 || len(merged.PadBuckets) != 2 || merged.TLSMinVersion != "1.2" {
		t.Fatalf("parent fallback lost: %+v", merged)
	}
	if axes.pad == nil || len(axes.pad.buckets) != 2 || axes.pad.maxPad != 32 || axes.pad.bigPadMax != 1024 {
		t.Fatalf("pad config from merged axes wrong: %+v", axes.pad)
	}
	if axes.rtc.Chunk != 900 || axes.rtc.Window != 64 || axes.rtc.RtoMinMs != 120 || axes.rtc.BufferCap != 256 || axes.rtc.KeepaliveEveryMs != 3000 {
		t.Fatalf("rtc option axes wrong: %+v", axes.rtc)
	}
	rc := rtcChannelParams(axes)
	if rc.Chunk != 900 || rc.Window != 64 || rc.RtoMinMs != 120 || rc.RtoMaxMs != 4000 || rc.BufferCap != 256 || rc.KeepaliveEvery != 3000*time.Millisecond {
		t.Fatalf("rtc channel params = %+v", rc)
	}
	if len(rc.PadBuckets) != 2 || rc.PadBuckets[0] != 512 || rc.MaxPad != 32 || rc.BigFramePadMax != 1024 {
		t.Fatalf("rtc pad params = %+v", rc)
	}
	// A zero candidate on a zero parent resolves to pure defaults.
	defMerged, defAxes, err := axesOrDefault(option.HydraAdaptiveCandidateOptions{}, option.HydraAdaptiveCandidateOptions{}, nil)
	if err != nil || defMerged.FragFirstMin != 0 || defAxes.split.Disorder || defAxes.pad.buckets != nil {
		t.Fatalf("default resolution = %+v / %+v err %v, want zero axes", defMerged, defAxes, err)
	}
	// A malformed pad ladder fails construction even through the parent.
	if _, _, err := axesOrDefault(option.HydraAdaptiveCandidateOptions{}, tuned, nil); err != nil {
		t.Fatalf("valid tuned parent must resolve: %v", err)
	}
	badParent := option.HydraAdaptiveCandidateOptions{PadBuckets: []uint32{512, 256}}
	if _, _, err := axesOrDefault(option.HydraAdaptiveCandidateOptions{}, badParent, nil); err == nil {
		t.Fatal("malformed parent pad ladder must fail closed")
	}
}

func TestPadConfigBuckets(t *testing.T) {
	if err := validatePadBuckets(nil); err != nil {
		t.Fatalf("nil buckets are valid: %v", err)
	}
	if err := validatePadBuckets([]uint32{65536, 256}); err == nil {
		t.Fatal("descending ladder must fail")
	}
	if err := validatePadBuckets([]uint32{256, 131072}); err == nil {
		t.Fatal("out-of-range member must fail")
	}
	nine := make([]uint32, 9)
	for i := range nine {
		nine[i] = uint32(256 << i)
	}
	if err := validatePadBuckets(nine); err == nil {
		t.Fatal("nine buckets must fail the amplification bound")
	}
	// Default config is byte-identical to the legacy helper's domain.
	for plainLen := 0; plainLen < 70000; plainLen += 997 {
		pad := padTarget(plainLen)
		if pad < 0 || pad > 4096 {
			t.Fatalf("padTarget(%d) = %d outside the legal domain", plainLen, pad)
		}
	}
	// A one-bucket, maxPad=1 config pins the pad draw to {0,1}.
	cfg := newPadConfig([]uint32{512}, 1, 1)
	for i := 0; i < 200; i++ {
		pad := cfg.padTargetFor(100) // need 119 -> bucket 512, slack capped to 1
		if pad != 0 && pad != 1 {
			t.Fatalf("custom config pad = %d, want 0 or 1", pad)
		}
	}
	// max_pad axis only lowers the cap (clamped to <=64 at resolvePadAxes).
	if got := newPadConfig(nil, 999, 8192); got.maxPad != MaxPad || got.bigPadMax != bigPadDefault {
		t.Fatalf("unclamped pad caps = %d/%d, want %d/%d", got.maxPad, got.bigPadMax, MaxPad, bigPadDefault)
	}
}

func TestCatalogueExpansionAttackCheckGuard(t *testing.T) {
	// Unit: the piece-budget math (tungstenite AttackCheck: >64 reads
	// averaging <128B is an instant mid-upgrade RST).
	for name, tc := range map[string]struct {
		firstMax, restMin uint32
		safe              bool
	}{
		"absent rest":          {64, 0, true},
		"floor safe 11":        {64, 11, true},
		"baseline 16":          {64, 16, true},
		"server fatal 8":       {64, 8, false},
		"server fatal 2":       {64, 2, false},
		"small first 12":       {16, 12, true},
		"tiny first huge rest": {1, 96, true},
	} {
		if got := attackCheckSafe(tc.firstMax, tc.restMin); got != tc.safe {
			t.Fatalf("%s: attackCheckSafe(%d,%d) = %v, want %v", name, tc.firstMax, tc.restMin, got, tc.safe)
		}
	}
	// Expansion: a below-floor rest ladder is an explicit recipe-level skip
	// (never a candidate, never a whole-expansion failure).
	cands, skips, err := CandidatesFromCatalogue(axisCatalogue(map[string]any{
		"frag_rest_min": float64(2),
	}), "")
	if err != nil || len(cands) != 0 {
		t.Fatalf("unsafe frag recipe must skip, got candidates=%v err=%v", cands, err)
	}
	if len(skips) != 1 || !strings.Contains(skips[0], "unsafe-param-frag_rest_min") {
		t.Fatalf("skips = %v, want explicit unsafe-param-frag_rest_min entry", skips)
	}
	// At the floor and above: expands normally.
	for _, rest := range []float64{11, 16, 96} {
		cands, skips, err := CandidatesFromCatalogue(axisCatalogue(map[string]any{
			"frag_rest_min": rest,
		}), "")
		if err != nil || len(cands) != 1 || len(skips) != 0 {
			t.Fatalf("rest_min %v: candidates=%v skips=%v err=%v, want one candidate", rest, cands, skips, err)
		}
	}
	// A bad recipe must not block its siblings.
	cat := axisCatalogue(map[string]any{"frag_rest_min": float64(1)})
	cat.Recipes = append(cat.Recipes, CatalogueRecipe{ID: "rec-good", Server: "srv", Transport: "wss", Params: map[string]any{"frag_rest_min": float64(32)}})
	cands, skips, err = CandidatesFromCatalogue(cat, "")
	if err != nil || len(cands) != 1 || cands[0].RecipeID != "rec-good" || len(skips) != 1 {
		t.Fatalf("sibling survival: candidates=%v skips=%v err=%v", cands, skips, err)
	}
}

func TestCatalogueExpansionDPIGateAxes(t *testing.T) {
	// dpi_gate with no threshold bakes the Rust default 0.5; explicit 0 is
	// the deliberate raise-on-everything value and stays 0.
	byThreshold := func(params map[string]any) option.HydraAdaptiveCandidateOptions {
		cands, _, err := CandidatesFromCatalogue(axisCatalogue(params), "")
		if err != nil || len(cands) != 1 {
			t.Fatalf("params %v: candidates=%v err=%v, want one candidate", params, cands, err)
		}
		return cands[0]
	}
	def := byThreshold(map[string]any{"dpi_gate": float64(1)})
	if !def.DPIGateEnabled || def.DPIGateThreshold != 0.5 {
		t.Fatalf("gate default = %v/%v, want true/0.5", def.DPIGateEnabled, def.DPIGateThreshold)
	}
	zero := byThreshold(map[string]any{"dpi_gate": "true", "dpi_threshold": float64(0)})
	if !zero.DPIGateEnabled || zero.DPIGateThreshold != 0 {
		t.Fatalf("gate explicit zero = %v/%v, want true/0 (verbatim)", zero.DPIGateEnabled, zero.DPIGateThreshold)
	}
	half := byThreshold(map[string]any{"dpi_gate": float64(1), "dpi_threshold": 0.42})
	if half.DPIGateThreshold != 0.42 {
		t.Fatalf("gate explicit threshold = %v, want 0.42", half.DPIGateThreshold)
	}
	off := byThreshold(nil)
	if off.DPIGateEnabled {
		t.Fatal("gate must default off")
	}
	// Out-of-domain thresholds fail closed.
	for _, bad := range []float64{-0.1, 1.5} {
		if _, _, err := CandidatesFromCatalogue(axisCatalogue(map[string]any{"dpi_gate": float64(1), "dpi_threshold": bad}), ""); err == nil {
			t.Fatalf("dpi_threshold %v must fail closed", bad)
		}
	}
	// Gate-on vs gate-off are distinct effective configurations.
	a := byThreshold(map[string]any{"dpi_gate": float64(1)})
	b := byThreshold(nil)
	a.ID, b.ID = "", ""
	a.RecipeID, b.RecipeID = "", ""
	aEnc, _ := json.Marshal(a)
	bEnc, _ := json.Marshal(b)
	if string(aEnc) == string(bEnc) {
		t.Fatal("dpi_gate on/off must marshal to different identities")
	}
}

func TestAxesDPIGateResolution(t *testing.T) {
	// Candidate off + parent on: inherits the parent gate and threshold.
	merged, axes, err := axesOrDefault(option.HydraAdaptiveCandidateOptions{},
		option.HydraAdaptiveCandidateOptions{DPIGateEnabled: true, DPIGateThreshold: 0.7}, nil)
	if err != nil || !merged.DPIGateEnabled || merged.DPIGateThreshold != 0.7 {
		t.Fatalf("parent gate inheritance = %+v err %v", merged, err)
	}
	if !axes.dpiGateEnabled || axes.dpiGateThreshold != 0.7 {
		t.Fatalf("carrier gate = %v/%v, want true/0.7", axes.dpiGateEnabled, axes.dpiGateThreshold)
	}
	// Candidate on with explicit 0: verbatim, parent threshold must NOT win.
	merged, axes, err = axesOrDefault(option.HydraAdaptiveCandidateOptions{DPIGateEnabled: true, DPIGateThreshold: 0},
		option.HydraAdaptiveCandidateOptions{DPIGateEnabled: true, DPIGateThreshold: 0.7}, nil)
	if err != nil || merged.DPIGateThreshold != 0 || axes.dpiGateThreshold != 0 {
		t.Fatalf("verbatim zero = merged %v carrier %v err %v, want 0/0", merged.DPIGateThreshold, axes.dpiGateThreshold, err)
	}
	// Candidate on without a threshold: the catalogue bakes 0.5, resolution
	// keeps 0.5 (not the parent's 0.7 — the candidate gate is on).
	merged, axes, err = axesOrDefault(option.HydraAdaptiveCandidateOptions{DPIGateEnabled: true, DPIGateThreshold: 0.5},
		option.HydraAdaptiveCandidateOptions{DPIGateEnabled: true, DPIGateThreshold: 0.7}, nil)
	if err != nil || axes.dpiGateThreshold != 0.5 {
		t.Fatalf("candidate threshold priority = %v err %v, want 0.5", axes.dpiGateThreshold, err)
	}
	// Both off: ungated, threshold concrete 0.5 in the carrier.
	_, axes, err = axesOrDefault(option.HydraAdaptiveCandidateOptions{}, option.HydraAdaptiveCandidateOptions{}, nil)
	if err != nil || axes.dpiGateEnabled || axes.dpiGateThreshold != dpiGateDefaultThreshold {
		t.Fatalf("default gate = %v/%v err %v", axes.dpiGateEnabled, axes.dpiGateThreshold, err)
	}
}
