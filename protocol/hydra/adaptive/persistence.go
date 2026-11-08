package adaptive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
)

const maxHintBytes = 16384

type winnerHint struct {
	Version  int    `json:"version"`
	Key      string `json:"key"`
	LastGood string `json:"last_good"`
}

func (c *Coordinator) stateError(err error) {
	if err != nil {
		c.state.StateError = fmt.Sprintf("adaptive state: %v", err)
	}
}

func (c *Coordinator) loadHint() {
	if !c.persistenceEnabled || c.cfg.StatePath == "" {
		return
	}
	entry, err := os.Lstat(c.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		c.stateError(err)
		return
	}
	if !entry.Mode().IsRegular() {
		c.stateError(errors.New("hint is not a regular file"))
		return
	}
	f, err := os.Open(c.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		c.stateError(err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		c.stateError(err)
		return
	}
	if !info.Mode().IsRegular() {
		c.stateError(errors.New("hint is not a regular file"))
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHintBytes+1))
	if err != nil {
		c.stateError(err)
		return
	}
	if len(b) > maxHintBytes {
		c.stateError(errors.New("hint exceeds size limit"))
		return
	}
	var h winnerHint
	if err = json.Unmarshal(b, &h); err != nil {
		c.stateError(err)
		return
	}
	if h.Version != 1 {
		c.stateError(errors.New("unsupported hint version"))
		return
	}
	if h.Key != c.cfg.StateKey {
		return
	}
	if indexOfCandidate(c.cfg.Candidates, h.LastGood) < 0 {
		c.stateError(errors.New("unknown hint candidate"))
		return
	}
	c.state.LastGood = h.LastGood
	c.state.StateLoaded = true
}

func syncParent(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Serialized with promotion and ResetNetwork under mu. State is only a hint;
// no persisted bytes can manufacture a candidate or a verified connection.
func (c *Coordinator) saveHint() {
	c.state.StateSaved = false
	if !c.persistenceEnabled || c.cfg.StatePath == "" {
		return
	}
	// A promoted candidate that is no longer in the current set (a swap
	// raced an in-flight attempt on a removed ID) must NOT be persisted
	// (audit G2, amendment 3): loadHint would reject the unknown ID on the
	// next start and surface a bogus StateError while the real hint is
	// effectively lost. The in-memory session preference (state.LastGood)
	// is kept.
	if indexOfCandidate(c.cfg.Candidates, c.state.LastGood) < 0 {
		return
	}
	err := c.writeHint()
	c.stateError(err)
	c.state.StateSaved = err == nil
}
func (c *Coordinator) writeHint() error {
	b, err := json.Marshal(winnerHint{1, c.cfg.StateKey, c.state.LastGood})
	if err != nil {
		return err
	}
	if len(b) > maxHintBytes {
		return errors.New("hint exceeds size limit")
	}
	return writeAtomic(c.cfg.StatePath, ".hydra-winner-*", b)
}
func (c *Coordinator) clearHint() {
	c.state.StateSaved = false
	if c.cfg.StatePath == "" {
		return
	}
	err := os.Remove(c.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		err = syncParent(c.cfg.StatePath)
	}
	c.stateError(err)
}

// Catalogue watermark (audit G4): anti-rollback state for the signed
// capability catalogue. The catalogue loader takes a minimum sequence
// (LoadAndVerifyCatalogue's minSeq); the caller persists the highest VERIFIED
// seq and passes it back as minSeq on the next load, so a re-served older
// (possibly attacker-controlled) document is rejected as a replay. The
// revocation union is kept so a revocation survives even when a later
// document's revocation list would otherwise be the only record. The file
// lives beside the winner-hint state (same directory, fixed name) and is
// keyed by a fingerprint of the catalogue's Ed25519 root pubkey, so two
// different control roots never gate each other.
const (
	catalogueWatermarkFileName = "catalogue-watermark.json"
	maxWatermarkBytes          = 65536
	// maxWatermarkRevokedIDs bounds the persisted revocation union. Sources
	// are verified documents; exceeding the bound means a hostile or broken
	// producer, and the merge refuses instead of growing without bound.
	maxWatermarkRevokedIDs = 1024
)

// CatalogueWatermark is the persisted replay-protection state.
type CatalogueWatermark struct {
	Version    int      `json:"version"`
	Key        string   `json:"key"` // hex sha256 of the catalogue root pubkey
	MaxSeq     uint64   `json:"max_seq"`
	RevokedIDs []string `json:"revoked_ids,omitempty"`
}

// CatalogueWatermarkPath maps the adaptive state path of one group onto the
// watermark file: same directory, fixed name. The watermark describes the
// CATALOGUE (one per install), not one group, so the fixed name is correct
// even with several groups sharing the directory.
func CatalogueWatermarkPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), catalogueWatermarkFileName)
}

// CatalogueWatermarkKey fingerprints the catalogue's root pubkey. Callers
// pass the SAME root they verify signatures against.
func CatalogueWatermarkKey(rootPub []byte) string {
	sum := sha256.Sum256(rootPub)
	return hex.EncodeToString(sum[:])
}

// LoadCatalogueWatermark reads the persisted watermark keyed alongside
// statePath. ok=false means absent (or a DIFFERENT control root's file —
// treated as absent, mirroring the winner-hint key rule). An error means the
// file exists but is unusable (corrupt, unsupported version, oversize): the
// caller MUST NOT verify with a weakened (zero) watermark in that case — it
// should fail the refresh cycle and keep serving the current candidate set.
func LoadCatalogueWatermark(statePath, key string) (CatalogueWatermark, bool, error) {
	path := CatalogueWatermarkPath(statePath)
	entry, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return CatalogueWatermark{}, false, nil
	}
	if err != nil {
		return CatalogueWatermark{}, false, err
	}
	if !entry.Mode().IsRegular() {
		return CatalogueWatermark{}, false, errors.New("catalogue watermark is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return CatalogueWatermark{}, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxWatermarkBytes+1))
	if err != nil {
		return CatalogueWatermark{}, false, err
	}
	if len(b) > maxWatermarkBytes {
		return CatalogueWatermark{}, false, errors.New("catalogue watermark exceeds size limit")
	}
	var w CatalogueWatermark
	if err = json.Unmarshal(b, &w); err != nil {
		return CatalogueWatermark{}, false, err
	}
	if w.Version != 1 {
		return CatalogueWatermark{}, false, errors.New("unsupported catalogue watermark version")
	}
	if w.Key != key {
		return CatalogueWatermark{}, false, nil
	}
	return w, true, nil
}

// StoreCatalogueWatermark atomically persists the watermark: 0600, temp file
// + fsync + rename + directory sync, exactly like the winner hint. The
// revocation list is stored canonical (sorted, deduplicated) so every reader
// sees the same bytes for the same state.
func StoreCatalogueWatermark(statePath string, w CatalogueWatermark) error {
	if w.Version != 1 {
		return errors.New("catalogue watermark version must be 1")
	}
	if w.Key == "" {
		return errors.New("catalogue watermark key must not be empty")
	}
	w.RevokedIDs = append([]string(nil), w.RevokedIDs...)
	slices.Sort(w.RevokedIDs)
	w.RevokedIDs = slices.Compact(w.RevokedIDs)
	b, err := json.Marshal(w)
	if err != nil {
		return err
	}
	if len(b) > maxWatermarkBytes {
		return errors.New("catalogue watermark exceeds size limit")
	}
	return writeAtomic(CatalogueWatermarkPath(statePath), ".hydra-watermark-*", b)
}

// MergeCatalogueWatermark folds one VERIFIED document (its seq and
// revocation list) into the current watermark. The sequence only moves
// forward; the revocation list is a sorted, deduplicated union. Version and
// key are normalized to the caller's.
func MergeCatalogueWatermark(w CatalogueWatermark, key string, seq uint64, revoked []string) (CatalogueWatermark, error) {
	out := CatalogueWatermark{Version: 1, Key: key, MaxSeq: w.MaxSeq}
	if seq > out.MaxSeq {
		out.MaxSeq = seq
	}
	seen := make(map[string]bool, len(w.RevokedIDs)+len(revoked))
	out.RevokedIDs = make([]string, 0, len(w.RevokedIDs)+len(revoked))
	for _, id := range append(append([]string(nil), w.RevokedIDs...), revoked...) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out.RevokedIDs = append(out.RevokedIDs, id)
	}
	if len(out.RevokedIDs) > maxWatermarkRevokedIDs {
		return CatalogueWatermark{}, fmt.Errorf("catalogue revocation union exceeds %d ids", maxWatermarkRevokedIDs)
	}
	sort.Strings(out.RevokedIDs)
	return out, nil
}

// writeAtomic replaces path with b atomically (temp file in the same
// directory, 0600, fsync, rename, directory sync). pattern names the temp
// file; it must stay collision-free within the directory.
func writeAtomic(path, pattern string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), pattern)
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncParent(path)
}
