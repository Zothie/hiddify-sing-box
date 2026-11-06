package adaptive

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testResource struct {
	done chan struct{}
	once sync.Once
}

func resource() *testResource                 { return &testResource{done: make(chan struct{})} }
func (r *testResource) Done() <-chan struct{} { return r.done }
func (r *testResource) Close() error          { r.once.Do(func() { close(r.done) }); return nil }
func config() Config {
	return Config{Candidates: []Candidate{{ID: "a"}, {ID: "b"}, {ID: "c"}}, LastGood: "c", AttemptTimeout: time.Second, Backoff: time.Millisecond, MaxBackoff: 4 * time.Millisecond}
}
func acquire(t *testing.T, c *Coordinator) Resource {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, e := c.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestSharedAndCancellationAndDead(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	cfg := config()
	cfg.Connect = func(ctx context.Context, _ Candidate) (Resource, error) {
		calls.Add(1)
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return resource(), nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, e := New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.Acquire(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan Resource, 40)
	for range 40 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- acquire(t, c) }()
	}
	close(gate)
	wg.Wait()
	close(results)
	var first Resource
	for r := range results {
		if first == nil {
			first = r
		}
		if r != first {
			t.Fatal("not shared")
		}
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
	first.Close()
	if acquire(t, c) == first {
		t.Fatal("dead reused")
	}
}
func TestFairBackoffAndVerifyCleanup(t *testing.T) {
	cfg := config()
	var mu sync.Mutex
	var ids []string
	var delays []time.Duration
	var resources []*testResource
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg.Connect = func(_ context.Context, c Candidate) (Resource, error) {
		mu.Lock()
		defer mu.Unlock()
		ids = append(ids, c.ID)
		r := resource()
		resources = append(resources, r)
		return r, nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return errors.New("not verified") }
	cfg.Wait = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		delays = append(delays, d)
		n := len(delays)
		mu.Unlock()
		if n == 4 {
			cancel()
		}
		return ctx.Err()
	}
	c, e := New(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_, _ = c.Acquire(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 12 {
		t.Fatal(ids)
	}
	// Scored fair rotation: last-good first, then one full epoch per candidate.
	// After every candidate carries the same attempts/failures the tie-break
	// returns to config order (a, b, c).
	want := []string{"c", "a", "b", "a", "b", "c", "a", "b", "c", "a", "b", "c"}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatal(ids)
		}
	}
	for i, d := range []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond, 4 * time.Millisecond} {
		if delays[i] != d {
			t.Fatal(delays)
		}
	}
	for _, r := range resources {
		select {
		case <-r.done:
		default:
			t.Fatal("verify failure leaked")
		}
	}
}
func TestFenceLateConnect(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "reset"}[reset], func(t *testing.T) {
			cfg := config()
			started := make(chan struct{})
			release := make(chan struct{})
			late := resource()
			var calls atomic.Int32
			cfg.Connect = func(context.Context, Candidate) (Resource, error) {
				if calls.Add(1) == 1 {
					close(started)
					<-release
					return late, nil
				}
				return resource(), nil
			}
			cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
			c, e := New(context.Background(), cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			result := make(chan Resource, 1)
			go func() { r, _ := c.Acquire(context.Background()); result <- r }()
			<-started
			if reset {
				c.ResetNetwork()
			} else {
				c.Close()
			}
			close(release)
			select {
			case <-late.done:
			case <-time.After(time.Second):
				t.Fatal("late leaked")
			}
			select {
			case r := <-result:
				if reset && r == late {
					t.Fatal("stale promoted")
				}
			case <-time.After(time.Second):
				t.Fatal("waiter stuck")
			}
		})
	}
}
func TestOverallTimeout(t *testing.T) {
	cfg := config()
	cfg.AttemptTimeout = 10 * time.Millisecond
	var verifies atomic.Int32
	cfg.Connect = func(ctx context.Context, _ Candidate) (Resource, error) { return resource(), nil }
	cfg.Verify = func(ctx context.Context, _ Candidate, _ Resource) error {
		verifies.Add(1)
		<-ctx.Done()
		return ctx.Err()
	}
	c, e := New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Millisecond)
	defer cancel()
	if _, e = c.Acquire(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if verifies.Load() < 2 {
		t.Fatal("no retry")
	}
	_ = c.Snapshot()
}
func TestValidation(t *testing.T) {
	cfg := config()
	if _, e := New(context.Background(), cfg); e == nil {
		t.Fatal("callbacks required")
	}
}

// A callback returning a typed nil inside the Resource interface must be
// treated as a failure, never handed to Close.
func TestTypedNilResourceFailsClosed(t *testing.T) {
	cfg := config()
	cfg.Connect = func(context.Context, Candidate) (Resource, error) {
		return (*testResource)(nil), nil
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Acquire(ctx); err == nil {
		t.Fatal("typed nil resource was promoted")
	}
}
