package adaptive

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCanceledWaiterDoesNotCancelSharedAttempt(t *testing.T) {
	cfg := config()
	started := make(chan struct{})
	release := make(chan struct{})
	r := resource()
	var calls atomic.Int32
	cfg.Connect = func(ctx context.Context, _ Candidate) (Resource, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return r, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	cfg.Verify = func(_ context.Context, _ Candidate, got Resource) error {
		if got != r {
			return errors.New("wrong resource")
		}
		return nil
	}
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { _, err := c.Acquire(ctx); finished <- err }()
	<-started
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if acquire(t, c) != r || calls.Load() != 1 {
		t.Fatal("shared work canceled")
	}
}

func TestResetDuringIgnoringVerify(t *testing.T) {
	cfg := config()
	started := make(chan struct{})
	release := make(chan struct{})
	old := resource()
	var calls atomic.Int32
	cfg.Connect = func(context.Context, Candidate) (Resource, error) {
		if calls.Add(1) == 1 {
			return old, nil
		}
		return resource(), nil
	}
	cfg.Verify = func(_ context.Context, _ Candidate, r Resource) error {
		if r == old {
			close(started)
			<-release
		}
		return nil
	}
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() { _, _ = c.Acquire(context.Background()) }()
	<-started
	c.ResetNetwork()
	select {
	case <-old.done:
	case <-time.After(time.Second):
		t.Fatal("reset did not close verifying resource")
	}
	close(release)
	replacement := acquire(t, c)
	if replacement == old {
		t.Fatal("stale verification promoted")
	}
	select {
	case <-old.done:
	case <-time.After(time.Second):
		t.Fatal("late verification leaked")
	}
}

func TestConnectAndVerifyShareDeadline(t *testing.T) {
	var rDeadline sync.Map
	cfg := config()
	cfg.AttemptTimeout = 40 * time.Millisecond
	deadlines := make(chan [2]time.Time, 1)
	cfg.Connect = func(ctx context.Context, _ Candidate) (Resource, error) {
		d, _ := ctx.Deadline()
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		r := resource()
		rDeadline.Store(r, d)
		return r, nil
	}
	cfg.Verify = func(ctx context.Context, _ Candidate, r Resource) error {
		d, _ := ctx.Deadline()
		original, _ := rDeadline.LoadAndDelete(r)
		select {
		case deadlines <- [2]time.Time{original.(time.Time), d}:
		default:
		}
		return nil
	}
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	acquire(t, c)
	pair := <-deadlines
	if pair[0] != pair[1] {
		t.Fatal("timeout restarted for verification")
	}
}
