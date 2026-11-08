package hydra

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// G5: the expansion wrapper enforces the recovery budget on the EXPANSION
// OUTPUT (every matching endpoint of every recipe), not on the document's
// recipe count. Policy: hint-first recovery makes the budget a worst-case
// epoch bound — a catalogue exceeding it must either split groups or the
// caller raises the budget explicitly. Fail-closed per mandate: no silent
// truncation.

// budgetTestDoc builds a signed catalogue whose single recipe selects
// exactly `endpoints` wss endpoints on one server, so the expansion yields
// exactly `endpoints` candidates.
func budgetTestDoc(t *testing.T, endpoints int) *Catalogue {
	t.Helper()
	eps := make([]CatalogueEndpoint, 0, endpoints)
	for i := range endpoints {
		eps = append(eps, CatalogueEndpoint{Transport: "wss", Host: "srv.example", Port: 443, Path: "/p" + string(rune('a'+i))})
	}
	cat := Catalogue{Schema: 1, Seq: 7, IssuedAt: 1, ExpiresAt: 1893456000,
		Servers: []CatalogueServer{{ID: "srv", Pubkey: encodeB64(make([]byte, 32)), Endpoints: eps}},
		Recipes: []CatalogueRecipe{{ID: "web", Server: "srv", Transport: "wss"}},
	}
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

func TestExpandCatalogueBudgetExceededFailClosed(t *testing.T) {
	verified := budgetTestDoc(t, 4)
	candidates, skips, err := ExpandCatalogueCandidates(verified, "", 10*time.Second, 0)
	if err == nil {
		t.Fatalf("4 candidates x 10s must exceed the default 30s budget: got %d candidates", len(candidates))
	}
	if candidates != nil || skips != nil {
		t.Fatalf("fail-closed: candidates=%d skips=%d, want nil/nil", len(candidates), len(skips))
	}
	var be *CatalogueBudgetError
	if !errors.As(err, &be) {
		t.Fatalf("error type %T, want *CatalogueBudgetError: %v", err, err)
	}
	if be.Seq != 7 || be.Candidates != 4 || be.AttemptTimeout != 10*time.Second || be.Budget != 30*time.Second {
		t.Fatalf("budget error numbers: seq=%d candidates=%d attempt=%s budget=%s", be.Seq, be.Candidates, be.AttemptTimeout, be.Budget)
	}
	msg := be.Error()
	for _, want := range []string{"seq 7", "4 candidates", "10s", "30s"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must name %q", msg, want)
		}
	}
}

func TestExpandCatalogueBudgetBoundaryAccepted(t *testing.T) {
	verified := budgetTestDoc(t, 3)
	candidates, skips, err := ExpandCatalogueCandidates(verified, "", 10*time.Second, 0)
	if err != nil {
		t.Fatalf("3 candidates x 10s = 30s must fit the default 30s budget: %v", err)
	}
	if len(candidates) != 3 || len(skips) != 0 {
		t.Fatalf("candidates=%d skips=%d, want 3/0", len(candidates), len(skips))
	}
}

func TestExpandCatalogueBudgetExplicitRaise(t *testing.T) {
	verified := budgetTestDoc(t, 4)
	candidates, _, err := ExpandCatalogueCandidates(verified, "", 10*time.Second, time.Minute)
	if err != nil {
		t.Fatalf("explicit 60s budget must accept 4 candidates x 10s: %v", err)
	}
	if len(candidates) != 4 {
		t.Fatalf("candidates=%d, want 4", len(candidates))
	}
}

func TestExpandCatalogueBudgetInvalidTimeout(t *testing.T) {
	verified := budgetTestDoc(t, 1)
	if _, _, err := ExpandCatalogueCandidates(verified, "", 0, 0); err == nil {
		t.Fatal("non-positive attempt timeout must be refused")
	}
}

func TestExpandCatalogueNilCatalogue(t *testing.T) {
	if _, _, err := ExpandCatalogueCandidates(nil, "", time.Second, 0); err == nil {
		t.Fatal("nil catalogue must be refused")
	}
}

// G4 replay protection end-to-end through the real loader: once the
// watermark records seq 42, a re-served older signed document (seq 41) is
// rejected with ErrCatalogueSeqTooLow — exactly what the refresher passes as
// minSeq when it loads the persisted watermark.
func TestCatalogueWatermarkReplayRejectsOlderSeq(t *testing.T) {
	payload, sig := loadFixture(t)
	if _, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), fixtureNow, 42); err != nil {
		t.Fatalf("fixture at its own watermark (seq 42) must verify: %v", err)
	}
	var cat Catalogue
	if err := json.Unmarshal(payload, &cat); err != nil {
		t.Fatal(err)
	}
	cat.Seq = 41
	older, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadAndVerifyCatalogue(older, ed25519.Sign(fixedPriv(t), older), fixedPub(t), fixtureNow, 42)
	if err == nil {
		t.Fatal("older-seq document must be rejected by the persisted watermark")
	}
	if got := errCode(t, err).Code; got != ErrCatalogueSeqTooLow {
		t.Fatalf("error code %q, want %q", got, ErrCatalogueSeqTooLow)
	}
}
