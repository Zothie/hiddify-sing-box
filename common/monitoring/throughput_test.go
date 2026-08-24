package monitoring

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestDisabledUnlessConfigured(t *testing.T) {
	if p := newThroughputProbe(nil); p != nil {
		t.Fatal("bulk probing must be off unless explicitly configured")
	}
}

// Bulk probing must be rare. Running it every cycle would spend the user's
// bandwidth and, worse, is the burst pattern that arms the censor's per-flow
// penalty -- manufacturing the outage we are trying to observe.
func TestOnlyRunsEveryNCycles(t *testing.T) {
	p := newThroughputProbe(&option.ThroughputProbeOptions{EveryNCycles: 4})
	due := 0
	for cycle := uint64(0); cycle < 20; cycle++ {
		if p.dueForCycle(cycle) {
			due++
		}
	}
	if due != 5 {
		t.Fatalf("expected 5 bulk probes in 20 cycles, got %d", due)
	}
}

// A node that just failed must not be hammered: the reported penalty lasts
// around 120s and is renewed by repeated attempts.
func TestFailureBacksOffExponentially(t *testing.T) {
	p := newThroughputProbe(&option.ThroughputProbeOptions{})
	now := time.Now()

	if p.suppressed("node", now) {
		t.Fatal("a node with no history must not be suppressed")
	}

	p.noteResult("node", false, now)
	if !p.suppressed("node", now.Add(30*time.Second)) {
		t.Fatal("a freshly failed node must be suppressed")
	}
	if p.suppressed("node", now.Add(throughputBackoffBase+time.Second)) {
		t.Fatal("suppression must expire")
	}

	// Second consecutive failure doubles the window.
	p.noteResult("node", false, now)
	if !p.suppressed("node", now.Add(throughputBackoffBase+time.Second)) {
		t.Fatal("second failure must extend the backoff")
	}

	// Success clears it immediately, so recovery is fast.
	p.noteResult("node", true, now)
	if p.suppressed("node", now) {
		t.Fatal("success must clear backoff")
	}
}

func TestBackoffIsCapped(t *testing.T) {
	p := newThroughputProbe(&option.ThroughputProbeOptions{})
	now := time.Now()
	for i := 0; i < 50; i++ {
		p.noteResult("node", false, now)
	}
	p.mu.Lock()
	d := p.backoff["node"].duration
	p.mu.Unlock()
	if d > throughputBackoffMax {
		t.Fatalf("backoff %v exceeded cap %v", d, throughputBackoffMax)
	}
}

// An impossible pass mark would evict every node, so it is clamped.
func TestMinCarriedBytesClampedToRequestSize(t *testing.T) {
	p := newThroughputProbe(&option.ThroughputProbeOptions{
		Bytes:           32 * 1024,
		MinCarriedBytes: 999 * 1024,
	})
	if p.minCarriedBytes > p.bytes {
		t.Fatalf("pass mark %d exceeds request size %d", p.minCarriedBytes, p.bytes)
	}
}

func TestJitterStaysWithinBound(t *testing.T) {
	p := newThroughputProbe(&option.ThroughputProbeOptions{
		MaxJitter: badoption.Duration(2 * time.Second),
	})
	for i := 0; i < 200; i++ {
		if j := p.jitter(); j < 0 || j >= 2*time.Second {
			t.Fatalf("jitter %v out of bounds", j)
		}
	}
}

func TestDefaultsAreSane(t *testing.T) {
	p := newThroughputProbe(&option.ThroughputProbeOptions{})
	// The request must cross the ~16-20KB freeze threshold or the probe is
	// blind to the exact failure it exists to detect.
	if p.bytes <= 20*1024 {
		t.Fatalf("default request size %d does not cross the freeze threshold", p.bytes)
	}
	if p.minCarriedBytes <= 20*1024 {
		t.Fatalf("default pass mark %d is below the freeze threshold", p.minCarriedBytes)
	}
	if p.everyNCycles < 2 {
		t.Fatal("default cadence is too aggressive")
	}
}
