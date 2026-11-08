package adaptive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Audit G2: the catalogue-runtime hot swap. ReplaceCandidates must swap the
// live sweep set atomically, keep stats for surviving ids, clamp the
// round-robin cursor when the set shrinks, and (amendment 3) never persist a
// hint for a candidate that is no longer in the set.

func TestReplaceCandidatesSwapsLiveSet(t *testing.T) {
	cfg := config()
	cfg.Connect = func(ctx context.Context, _ Candidate) (Resource, error) {
		return resource(), nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if acquire(t, c) == nil {
		t.Fatal("no resource")
	}
	snap := c.Snapshot()
	if snap.CandidateCount != 3 || snap.SwapGeneration != 0 {
		t.Fatalf("initial snapshot: count=%d swaps=%d", snap.CandidateCount, snap.SwapGeneration)
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: "x"}, {ID: "y"}}); err != nil {
		t.Fatal(err)
	}
	snap = c.Snapshot()
	if snap.CandidateCount != 2 || snap.SwapGeneration != 1 {
		t.Fatalf("post-swap snapshot: count=%d swaps=%d", snap.CandidateCount, snap.SwapGeneration)
	}
	if snap.ActiveID == "" {
		t.Fatal("swap must not interrupt the active resource")
	}
	// Invalid sets are rejected without touching state.
	if err := c.ReplaceCandidates(nil); err == nil {
		t.Fatal("empty set must be rejected")
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: "x"}, {ID: "x"}}); err == nil {
		t.Fatal("duplicate ids must be rejected")
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: ""}}); err == nil {
		t.Fatal("empty id must be rejected")
	}
	if snap = c.Snapshot(); snap.CandidateCount != 2 || snap.SwapGeneration != 1 {
		t.Fatalf("rejected swaps mutated state: count=%d swaps=%d", snap.CandidateCount, snap.SwapGeneration)
	}
}

// TestReplaceCandidatesClampsCursor sweeps a failing set, shrinks it to one
// candidate and verifies the loop keeps attempting without an index panic
// (run under -race in CI).
func TestReplaceCandidatesClampsCursor(t *testing.T) {
	cfg := config()
	var attempts atomic.Int32
	cfg.Connect = func(ctx context.Context, _ Candidate) (Resource, error) {
		attempts.Add(1)
		return nil, errors.New("down")
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The run loop starts on the first Acquire; it keeps retrying since the
	// connect always fails.
	acquireCtx, cancelAcquire := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelAcquire()
	go func() { _, _ = c.Acquire(acquireCtx) }()
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && attempts.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	if attempts.Load() < 3 {
		t.Fatalf("sweep made no progress: %d attempts", attempts.Load())
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: "solo"}}); err != nil {
		t.Fatal(err)
	}
	// Wait for the NEW id specifically: an in-flight attempt on an old
	// candidate can still land after the swap (a swap never invalidates
	// in-flight work), so a raw attempt counter is not swap evidence.
	deadline = time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && c.Snapshot().PerCandidate["solo"] == 0 {
		time.Sleep(time.Millisecond)
	}
	snap := c.Snapshot()
	if snap.PerCandidate["solo"] == 0 {
		t.Fatalf("new set not attempted: %v", snap.PerCandidate)
	}
	if snap.CandidateCount != 1 {
		t.Fatalf("candidate count %d, want 1", snap.CandidateCount)
	}
}

func TestReplaceCandidatesKeepsStatsForSurvivor(t *testing.T) {
	cfg := config()
	cfg.Connect = func(ctx context.Context, cand Candidate) (Resource, error) {
		if cand.ID == "a" {
			return nil, errors.New("a fails")
		}
		r := resource()
		// Die quickly so the sweep keeps cycling and "a" gets attempted.
		time.AfterFunc(2*time.Millisecond, func() { _ = r.Close() })
		return r, nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	acquireCtx, cancelAcquire := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelAcquire()
	go func() { _, _ = c.Acquire(acquireCtx) }()
	// The hint-first first attempt lands on "c"; wait until the failing "a"
	// has been swept too.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && c.Snapshot().PerCandidate["a"] == 0 {
		time.Sleep(time.Millisecond)
	}
	before := c.Snapshot().PerCandidate
	if before["a"] == 0 {
		t.Fatalf("expected attempts on a: %v", before)
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: "b"}, {ID: "c"}, {ID: "d"}}); err != nil {
		t.Fatal(err)
	}
	after := c.Snapshot().PerCandidate
	if after["a"] != before["a"] {
		t.Fatalf("removed id's stats must survive for re-add: %v -> %v", before, after)
	}
	if after["b"] < before["b"] {
		t.Fatalf("survivor lost stats: %v -> %v", before, after)
	}
}

// Amendment 3: an in-flight attempt on a REMOVED candidate may still promote
// (a verified tunnel is a real resource), but the hint FILE must not be
// persisted for it — loadHint would reject the unknown id on the next start
// and surface a bogus StateError.
func TestReplaceCandidatesSkipsHintSaveForRemovedPromotion(t *testing.T) {
	dir := t.TempDir()
	cfg := config() // a, b, c
	cfg.StatePath = filepath.Join(dir, "winner.json")
	cfg.StateKey = "k"
	gate := make(chan struct{})
	var releaseOnce atomic.Bool
	cfg.Connect = func(ctx context.Context, _ Candidate) (Resource, error) {
		if releaseOnce.CompareAndSwap(false, true) {
			<-gate
		}
		return resource(), nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan struct{})
	go func() {
		_, _ = c.Acquire(context.Background())
		close(done)
	}()
	// Wait until the first attempt is in flight (the hint-first candidate
	// "c"), then swap the set so it is removed while its attempt is pending.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && c.Snapshot().Attempts == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: "d"}, {ID: "e"}}); err != nil {
		t.Fatal(err)
	}
	close(gate)
	<-done
	snap := c.Snapshot()
	// The in-flight REMOVED candidate ("c", the hint-first first attempt)
	// still promotes: a verified tunnel is a real resource and the swap
	// deliberately does not bump the generation.
	if snap.ActiveID != "c" || snap.LastGood != "c" {
		t.Fatalf("in-flight removed candidate must still promote: %+v", snap)
	}
	if snap.CandidateCount != 2 || snap.SwapGeneration != 1 {
		t.Fatalf("swap not recorded: %+v", snap)
	}
	if _, err := os.Stat(cfg.StatePath); !os.IsNotExist(err) {
		t.Fatalf("hint file must NOT exist after a removed candidate promoted: %v", err)
	}
	if snap.StateSaved || snap.StateError != "" {
		t.Fatalf("hint skip must be silent and clean: saved=%v err=%q", snap.StateSaved, snap.StateError)
	}
}

func TestReplaceCandidatesOnClosedCoordinator(t *testing.T) {
	cfg := config()
	cfg.Connect = func(ctx context.Context, _ Candidate) (Resource, error) {
		return resource(), nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if err := c.ReplaceCandidates([]Candidate{{ID: "x"}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed coordinator swap: %v", err)
	}
}
