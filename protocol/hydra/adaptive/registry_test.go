package adaptive

import (
	"fmt"
	"sync"
	"testing"
)

func TestRegistryRoundTrip(t *testing.T) {
	want := Snapshot{Generation: 3, ActiveID: "alpha", LastGood: "alpha", Attempts: 7}
	RegisterOutbound("reg-round-trip", func() Snapshot { return want })
	got, ok := SnapshotByTag("reg-round-trip")
	if !ok {
		t.Fatal("registered tag not found")
	}
	if got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
	UnregisterOutbound("reg-round-trip")
	if _, ok := SnapshotByTag("reg-round-trip"); ok {
		t.Fatal("unregistered tag still found")
	}
}

func TestRegistryUnknownTag(t *testing.T) {
	if _, ok := SnapshotByTag("reg-never-registered"); ok {
		t.Fatal("unknown tag reported as registered")
	}
}

func TestRegistryNilGetterIgnored(t *testing.T) {
	RegisterOutbound("reg-nil", nil)
	if _, ok := SnapshotByTag("reg-nil"); ok {
		t.Fatal("nil getter must not be registered")
	}
	UnregisterOutbound("reg-nil") // must stay a safe no-op
}

func TestRegistryReplacesStaleTag(t *testing.T) {
	RegisterOutbound("reg-stale", func() Snapshot { return Snapshot{Generation: 1} })
	RegisterOutbound("reg-stale", func() Snapshot { return Snapshot{Generation: 2} })
	got, ok := SnapshotByTag("reg-stale")
	if !ok {
		t.Fatal("tag missing after re-register")
	}
	if got.Generation != 2 {
		t.Fatalf("generation = %d, want 2 (latest registration wins)", got.Generation)
	}
	UnregisterOutbound("reg-stale")
	UnregisterOutbound("reg-stale") // idempotent
	if _, ok := SnapshotByTag("reg-stale"); ok {
		t.Fatal("tag resurrected after unregister")
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	const workers, loops = 8, 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			tag := fmt.Sprintf("reg-worker-%d", w)
			RegisterOutbound(tag, func() Snapshot { return Snapshot{Generation: uint64(w)} })
			for i := 0; i < loops; i++ {
				if s, ok := SnapshotByTag(tag); !ok || s.Generation != uint64(w) {
					t.Errorf("worker %d: snapshot = %+v ok = %v", w, s, ok)
					return
				}
				SnapshotByTag(fmt.Sprintf("reg-worker-%d", (w+1)%workers))
				SnapshotByTag("reg-never-registered")
			}
			UnregisterOutbound(tag)
		}(w)
	}
	wg.Wait()
	for w := 0; w < workers; w++ {
		if _, ok := SnapshotByTag(fmt.Sprintf("reg-worker-%d", w)); ok {
			t.Fatalf("worker %d tag still registered after unregister", w)
		}
	}
}
