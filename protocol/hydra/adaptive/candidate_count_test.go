package adaptive

import (
	"context"
	"testing"
)

// G2 contract: the snapshot surfaces the size of the live candidate set.
// CandidateCount is derived at Snapshot time from cfg, so a future
// ReplaceCandidates hot-swap that swaps cfg.Candidates is reflected without
// a separate update site.
func TestSnapshotCandidateCount(t *testing.T) {
	cfg := config() // 3 candidates: a, b, c
	cfg.Connect = func(context.Context, Candidate) (Resource, error) {
		return resource(), nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.Snapshot().CandidateCount; got != 3 {
		t.Fatalf("CandidateCount = %d, want 3", got)
	}
}

// SwapGeneration increments ONLY on ReplaceCandidates hot-swaps. Until such
// a swap lands it must stay 0, and ordinary lifecycle events (searches,
// network resets, attempt epochs) must never touch it.
func TestSnapshotSwapGenerationStaysZeroWithoutHotSwap(t *testing.T) {
	cfg := config()
	cfg.Connect = func(context.Context, Candidate) (Resource, error) {
		return resource(), nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.Snapshot().SwapGeneration; got != 0 {
		t.Fatalf("fresh SwapGeneration = %d, want 0", got)
	}
	// A network reset bumps Generation (attempt epoch), never SwapGeneration.
	c.ResetNetwork()
	snap := c.Snapshot()
	if snap.SwapGeneration != 0 {
		t.Fatalf("SwapGeneration after ResetNetwork = %d, want 0", snap.SwapGeneration)
	}
	if snap.Generation == 0 {
		t.Fatalf("Generation after ResetNetwork = 0, want non-zero")
	}
}

// ReplaceCandidates hot-swaps are the only SwapGeneration increment site.
// Every accepted swap bumps it by exactly one and the snapshot must show the
// new set size immediately; rejected swaps (empty set, duplicate ids) must
// not move it.
func TestSwapGenerationIncrementsOnlyOnHotSwap(t *testing.T) {
	cfg := config()
	cfg.Connect = func(context.Context, Candidate) (Resource, error) { return resource(), nil }
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if got := c.Snapshot().SwapGeneration; got != 0 {
		t.Fatalf("fresh SwapGeneration = %d, want 0", got)
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: "x"}, {ID: "y"}}); err != nil {
		t.Fatal(err)
	}
	snap := c.Snapshot()
	if snap.SwapGeneration != 1 {
		t.Fatalf("SwapGeneration after first swap = %d, want 1", snap.SwapGeneration)
	}
	if snap.CandidateCount != 2 {
		t.Fatalf("CandidateCount after swap = %d, want 2", snap.CandidateCount)
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: "z"}}); err != nil {
		t.Fatal(err)
	}
	if got := c.Snapshot().SwapGeneration; got != 2 {
		t.Fatalf("SwapGeneration after second swap = %d, want 2", got)
	}
	// Rejected swaps must not increment.
	if err := c.ReplaceCandidates(nil); err == nil {
		t.Fatal("empty candidate set accepted")
	}
	if err := c.ReplaceCandidates([]Candidate{{ID: "dup"}, {ID: "dup"}}); err == nil {
		t.Fatal("duplicate candidate id accepted")
	}
	if got := c.Snapshot().SwapGeneration; got != 2 {
		t.Fatalf("rejected swap moved SwapGeneration to %d, want 2", got)
	}
}
