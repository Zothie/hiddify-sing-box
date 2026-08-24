package balancer

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
)

// fresh builds a history entry for a node that carried data.
func fresh(delay uint16, bytes int64, kbps uint32) *adapter.URLTestHistory {
	return &adapter.URLTestHistory{
		Time:           time.Now(),
		Delay:          delay,
		CarriedBytes:   bytes,
		ThroughputKBps: kbps,
		ThroughputTime: time.Now(),
	}
}

// frozen models the censor's signature failure: the latency probe succeeds
// beautifully (a tiny delay, because the handshake completes and a HEAD
// transfers no body) but the node moved no real bytes.
func frozen(delay uint16) *adapter.URLTestHistory {
	return &adapter.URLTestHistory{
		Time:           time.Now(),
		Delay:          delay,
		CarriedBytes:   0,
		ThroughputKBps: 0,
		ThroughputTime: time.Now(),
	}
}

// unmeasured models a node the slow bulk probe has not reached yet.
func unmeasured(delay uint16) *adapter.URLTestHistory {
	return &adapter.URLTestHistory{Time: time.Now(), Delay: delay}
}

type fakeOutbound struct {
	adapter.Outbound
	tag string
}

func (f *fakeOutbound) Tag() string { return f.tag }

func outs(tags ...string) []adapter.Outbound {
	var res []adapter.Outbound
	for _, t := range tags {
		res = append(res, &fakeOutbound{tag: t})
	}
	return res
}

func tags(list []adapter.Outbound) []string {
	var res []string
	for _, o := range list {
		res = append(res, o.Tag())
	}
	return res
}

// This is the central claim of the whole change: a frozen node that wins on
// latency must lose to a slower node that actually carries data.
func TestFrozenNodeEvictedDespiteBestLatency(t *testing.T) {
	list := outs("moscow-relay", "finland-exit")
	history := map[string]*adapter.URLTestHistory{
		// Nearby relay: superb 3ms ping, carries nothing. Every latency-based
		// strategy would pick this one.
		"moscow-relay": frozen(3),
		// Distant exit: 25ms, but genuinely moves 128KB at 900 KB/s.
		"finland-exit": fresh(25, 128*1024, 900),
	}

	got := tags(rank(list, history, time.Now()))
	if len(got) != 1 || got[0] != "finland-exit" {
		t.Fatalf("expected only finland-exit to survive, got %v", got)
	}

	// Sanity-check the counterfactual: pure latency ordering picks the frozen
	// node, which is the bug this change exists to fix.
	if getTagDelay("moscow-relay", history) >= getTagDelay("finland-exit", history) {
		t.Fatal("test setup wrong: frozen node should have the better latency")
	}
}

// Among nodes that all genuinely work, the fastest must win -- not the nearest.
func TestRanksProvenNodesBySpeedNotLatency(t *testing.T) {
	list := outs("near-slow", "far-fast")
	history := map[string]*adapter.URLTestHistory{
		"near-slow": fresh(3, 128*1024, 100),   // closest, but 100 KB/s
		"far-fast":  fresh(26, 128*1024, 2000), // furthest, but 2 MB/s
	}

	got := tags(rank(list, history, time.Now()))
	if got[0] != "far-fast" {
		t.Fatalf("expected far-fast ranked first by goodput, got %v", got)
	}
}

// Equal speed falls back to latency as a tie-break.
func TestTieBreaksOnLatency(t *testing.T) {
	list := outs("far", "near")
	history := map[string]*adapter.URLTestHistory{
		"far":  fresh(200, 128*1024, 500),
		"near": fresh(10, 128*1024, 500),
	}
	got := tags(rank(list, history, time.Now()))
	if got[0] != "near" {
		t.Fatalf("expected near first on tie-break, got %v", got)
	}
}

// Before any bulk probe has run, selection must not collapse: nothing is proven
// but nothing is proven dead either, so fall back to latency order.
func TestFailsOpenWhenNothingMeasuredYet(t *testing.T) {
	list := outs("a", "b")
	history := map[string]*adapter.URLTestHistory{
		"a": unmeasured(50),
		"b": unmeasured(10),
	}
	got := tags(rank(list, history, time.Now()))
	if len(got) != 2 || got[0] != "b" {
		t.Fatalf("expected latency-ordered fallback [b a], got %v", got)
	}
}

// Stale evidence must not be trusted forever.
func TestStaleThroughputIsNotProof(t *testing.T) {
	list := outs("old")
	h := fresh(10, 128*1024, 900)
	h.ThroughputTime = time.Now().Add(-2 * throughputStaleAfter)
	history := map[string]*adapter.URLTestHistory{"old": h}

	if carriesData(history["old"], time.Now()) {
		t.Fatal("stale throughput evidence must not count as proof")
	}
	// Still returned via fail-open rather than dropped.
	if got := tags(rank(list, history, time.Now())); len(got) != 1 {
		t.Fatalf("expected fail-open to still offer the node, got %v", got)
	}
}

// When every node is both frozen and unreachable there is no good answer, but
// returning nothing would guarantee an outage. Something must come back.
func TestNeverReturnsEmpty(t *testing.T) {
	list := outs("x", "y")
	history := map[string]*adapter.URLTestHistory{
		"x": frozen(monitoring.TimeoutDelay),
		"y": frozen(monitoring.TimeoutDelay),
	}
	if got := rank(list, history, time.Now()); len(got) == 0 {
		t.Fatal("rank must never return an empty list")
	}
}

// A node proven dead by the bulk probe must lose to one merely unmeasured only
// when at least one node is proven alive; if none are proven, both stay.
func TestProvenAliveBeatsUnmeasured(t *testing.T) {
	list := outs("unmeasured-fast", "proven-slow")
	history := map[string]*adapter.URLTestHistory{
		"unmeasured-fast": unmeasured(1),
		"proven-slow":     fresh(300, 128*1024, 50),
	}
	got := tags(rank(list, history, time.Now()))
	if len(got) != 1 || got[0] != "proven-slow" {
		t.Fatalf("proof of carrying data must outrank an unproven fast ping, got %v", got)
	}
}
