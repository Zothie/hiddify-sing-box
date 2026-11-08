package adaptive

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func watermarkKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return CatalogueWatermarkKey(pub)
}

// G4: the catalogue watermark is a separate file next to the winner hint,
// 0600, atomic write (no temp litter), keyed by the control root pubkey.
func TestCatalogueWatermarkRoundTrip(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "group.json")
	key := watermarkKey(t)
	in := CatalogueWatermark{Version: 1, Key: key, MaxSeq: 42, RevokedIDs: []string{"srv-a", "recipe-b"}}
	if err := StoreCatalogueWatermark(statePath, in); err != nil {
		t.Fatalf("store: %v", err)
	}
	out, ok, err := LoadCatalogueWatermark(statePath, key)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ok {
		t.Fatal("stored watermark must load back")
	}
	if out.MaxSeq != 42 || !slices.Equal(out.RevokedIDs, []string{"recipe-b", "srv-a"}) || out.Version != 1 || out.Key != key {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	info, err := os.Stat(CatalogueWatermarkPath(statePath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("watermark mode %v, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "catalogue-watermark.json" {
		t.Fatalf("atomic write left litter: %v", entries)
	}
}

func TestCatalogueWatermarkAbsent(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "group.json")
	_, ok, err := LoadCatalogueWatermark(statePath, watermarkKey(t))
	if err != nil {
		t.Fatalf("absent watermark must not error: %v", err)
	}
	if ok {
		t.Fatal("absent watermark must report ok=false")
	}
}

func TestCatalogueWatermarkKeyMismatchIsAbsent(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "group.json")
	if err := StoreCatalogueWatermark(statePath, CatalogueWatermark{Version: 1, Key: watermarkKey(t), MaxSeq: 9}); err != nil {
		t.Fatal(err)
	}
	_, ok, err := LoadCatalogueWatermark(statePath, watermarkKey(t))
	if err != nil || ok {
		t.Fatalf("a different control root's watermark must be ignored: ok=%v err=%v", ok, err)
	}
}

func TestCatalogueWatermarkCorrupt(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "group.json")
	if err := StoreCatalogueWatermark(statePath, CatalogueWatermark{Version: 1, Key: watermarkKey(t), MaxSeq: 9}); err != nil {
		t.Fatal(err)
	}
	path := CatalogueWatermarkPath(statePath)
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCatalogueWatermark(statePath, watermarkKey(t)); err == nil {
		t.Fatal("corrupt watermark must error (the caller must never verify with a weakened watermark)")
	}
}

func TestCatalogueWatermarkUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "group.json")
	if err := StoreCatalogueWatermark(statePath, CatalogueWatermark{Version: 1, Key: watermarkKey(t), MaxSeq: 9}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(CatalogueWatermarkPath(statePath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CatalogueWatermarkPath(statePath), []byte(strings.Replace(string(raw), `"version":1`, `"version":2`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCatalogueWatermark(statePath, watermarkKey(t)); err == nil {
		t.Fatal("unsupported watermark version must error")
	}
}

func TestCatalogueWatermarkOversize(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "group.json")
	path := CatalogueWatermarkPath(statePath)
	if err := os.WriteFile(path, make([]byte, maxWatermarkBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCatalogueWatermark(statePath, watermarkKey(t)); err == nil {
		t.Fatal("oversize watermark must error")
	}
}

func TestCatalogueWatermarkDirectoryMissing(t *testing.T) {
	// A caller may store before the state dir exists only by accident; the
	// store must surface the error, not create directories silently.
	statePath := filepath.Join(t.TempDir(), "missing", "group.json")
	if err := StoreCatalogueWatermark(statePath, CatalogueWatermark{Version: 1, Key: watermarkKey(t), MaxSeq: 9}); err == nil {
		t.Fatal("store into a missing directory must error")
	}
}

func TestMergeCatalogueWatermark(t *testing.T) {
	key := watermarkKey(t)
	// Forward seq and union.
	merged, err := MergeCatalogueWatermark(CatalogueWatermark{Version: 1, Key: key, MaxSeq: 42, RevokedIDs: []string{"srv-a"}}, key, 43, []string{"srv-b", "srv-a"})
	if err != nil {
		t.Fatal(err)
	}
	if merged.MaxSeq != 43 || !slices.Equal(merged.RevokedIDs, []string{"srv-a", "srv-b"}) {
		t.Fatalf("merge forward: %+v", merged)
	}
	// Backward seq never rolls the watermark back; revocations still merge.
	merged, err = MergeCatalogueWatermark(CatalogueWatermark{Version: 1, Key: key, MaxSeq: 43, RevokedIDs: nil}, key, 2, []string{"srv-c"})
	if err != nil {
		t.Fatal(err)
	}
	if merged.MaxSeq != 43 || !slices.Equal(merged.RevokedIDs, []string{"srv-c"}) {
		t.Fatalf("merge backward: %+v", merged)
	}
	// Nil key on input is normalized; version stays 1.
	merged, err = MergeCatalogueWatermark(CatalogueWatermark{}, key, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Version != 1 || merged.Key != key || merged.MaxSeq != 5 {
		t.Fatalf("merge fresh: %+v", merged)
	}
}

func TestMergeCatalogueWatermarkCap(t *testing.T) {
	key := watermarkKey(t)
	old := CatalogueWatermark{Version: 1, Key: key}
	for i := range maxWatermarkRevokedIDs {
		old.RevokedIDs = append(old.RevokedIDs, "old"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if _, err := MergeCatalogueWatermark(old, key, 2, []string{"overflow"}); err == nil {
		t.Fatal("revocation union beyond the cap must error")
	}
}
