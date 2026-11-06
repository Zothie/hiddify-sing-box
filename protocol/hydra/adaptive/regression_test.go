package adaptive

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPreferredDoesNotConsumeRoundRobinEpoch(t *testing.T) {
	cfg := config()
	cfg.LastGood = "a"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ids []string
	cfg.Connect = func(_ context.Context, v Candidate) (Resource, error) {
		ids = append(ids, v.ID)
		return nil, errors.New("fail")
	}
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	waited := make(chan struct{})
	cfg.Wait = func(context.Context, time.Duration) error { close(waited); cancel(); return context.Canceled }
	c, e := New(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_, _ = c.Acquire(context.Background())
	<-waited
	if len(ids) != 3 || ids[0] != "a" || ids[1] != "b" || ids[2] != "c" {
		t.Fatalf("first epoch: %v", ids)
	}
}
func TestResetRestoresBaseBackoff(t *testing.T) {
	cfg := config()
	cfg.LastGood = ""
	cfg.Candidates = cfg.Candidates[:1]
	cfg.Connect = func(context.Context, Candidate) (Resource, error) { return nil, errors.New("fail") }
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	waits := make(chan time.Duration)
	cfg.Wait = func(ctx context.Context, d time.Duration) error { waits <- d; <-ctx.Done(); return ctx.Err() }
	c, e := New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	go func() { _, _ = c.Acquire(context.Background()) }()
	<-waits
	c.ResetNetwork()
	if d := <-waits; d != cfg.Backoff {
		t.Fatalf("reset delay %v", d)
	}
}
func TestWaitErrorTerminates(t *testing.T) {
	cfg := config()
	cfg.Connect = func(context.Context, Candidate) (Resource, error) { return nil, errors.New("fail") }
	cfg.Verify = func(context.Context, Candidate, Resource) error { return nil }
	cfg.Wait = func(context.Context, time.Duration) error { return errors.New("broken clock") }
	c, e := New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, e = c.Acquire(ctx)
	if !errors.Is(e, ErrClosed) {
		t.Fatalf("wait error did not terminate: %v", e)
	}
}
func TestBlockedCallbackBoundAcrossTimeoutAndReset(t *testing.T) {
	for _, verify := range []bool{false, true} {
		t.Run(map[bool]string{false: "connect", true: "verify"}[verify], func(t *testing.T) {
			cfg := config()
			cfg.AttemptTimeout = 5 * time.Millisecond
			release := make(chan struct{})
			defer close(release)
			started := make(chan struct{})
			r := resource()
			var calls atomic.Int32
			cfg.Connect = func(context.Context, Candidate) (Resource, error) {
				if calls.Add(1) == 1 {
					close(started)
				}
				if !verify {
					<-release
				}
				return r, nil
			}
			cfg.Verify = func(context.Context, Candidate, Resource) error { <-release; return nil }
			c, e := New(context.Background(), cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			go func() { _, _ = c.Acquire(context.Background()) }()
			<-started
			if verify {
				select {
				case <-r.done:
				case <-time.After(100 * time.Millisecond):
					t.Error("known resource not closed at timeout")
				}
			}
			for range 5 {
				c.ResetNetwork()
			}
			time.Sleep(30 * time.Millisecond)
			if n := calls.Load(); n != 1 {
				t.Errorf("outstanding callbacks: %d", n)
			}
			done := make(chan struct{})
			go func() { c.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("close blocked")
			}
		})
	}
}
