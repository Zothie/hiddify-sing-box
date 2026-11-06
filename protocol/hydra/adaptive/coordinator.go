// Package adaptive coordinates verified resources for a fixed, prevalidated candidate set.
package adaptive

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

type Candidate struct{ ID string }

// Resource is owned by the coordinator. Callers borrow it and must not close it.
// Done must be stable and close when the resource becomes unusable.
type Resource interface {
	Close() error
	Done() <-chan struct{}
}

type Config struct {
	Candidates     []Candidate
	LastGood       string
	AttemptTimeout time.Duration
	Backoff        time.Duration
	MaxBackoff     time.Duration
	Connect        func(context.Context, Candidate) (Resource, error)
	Verify         func(context.Context, Candidate, Resource) error
	// Jitter must return promptly. Its output is clamped to [Backoff, MaxBackoff].
	Jitter func(time.Duration) time.Duration
	// Wait must return on cancellation. Nil uses a context-aware timer.
	// A non-cancellation error closes the coordinator to prevent hot retries.
	Wait func(context.Context, time.Duration) error
}

type Snapshot struct {
	Generation uint64
	ActiveID   string
	LastGood   string
	Attempts   uint64
	Closed     bool
}

var ErrClosed = errors.New("adaptive coordinator closed")

// isNilResource reports plain nil and typed nil pointers. A typed nil inside
// the Resource interface would pass the == nil check and crash on Close.
func isNilResource(r Resource) bool {
	if r == nil {
		return true
	}
	value := reflect.ValueOf(r)
	switch value.Kind() {
	case reflect.Pointer, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice, reflect.UnsafePointer, reflect.Interface:
		return value.IsNil()
	default:
		return false
	}
}

type Coordinator struct {
	mu               sync.Mutex
	cfg              Config
	ctx              context.Context
	cancel           context.CancelFunc
	generation       context.Context
	cancelGeneration context.CancelFunc
	state            Snapshot
	active           Resource
	changed          chan struct{}
	wake             chan struct{}
	next             int
	preferred        bool
	degraded         bool
	lastPrewarm      time.Time
}

func New(parent context.Context, cfg Config) (*Coordinator, error) {
	if parent == nil || len(cfg.Candidates) == 0 || cfg.Connect == nil || cfg.Verify == nil || cfg.AttemptTimeout <= 0 || cfg.Backoff <= 0 || cfg.MaxBackoff < cfg.Backoff {
		return nil, errors.New("invalid adaptive configuration")
	}
	seen := make(map[string]bool)
	for _, v := range cfg.Candidates {
		if v.ID == "" || seen[v.ID] {
			return nil, fmt.Errorf("invalid candidate ID %q", v.ID)
		}
		seen[v.ID] = true
	}
	if cfg.LastGood != "" && !seen[cfg.LastGood] {
		return nil, errors.New("unknown last-good candidate")
	}
	cfg.Candidates = append([]Candidate(nil), cfg.Candidates...)
	if cfg.Wait == nil {
		cfg.Wait = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	ctx, cancel := context.WithCancel(parent)
	g, gcancel := context.WithCancel(ctx)
	c := &Coordinator{cfg: cfg, ctx: ctx, cancel: cancel, generation: g, cancelGeneration: gcancel, changed: make(chan struct{}), wake: make(chan struct{}, 1), preferred: true, state: Snapshot{Generation: 1, LastGood: cfg.LastGood}}
	context.AfterFunc(ctx, func() { c.Close() })
	go c.run()
	return c, nil
}
func (c *Coordinator) signal() { close(c.changed); c.changed = make(chan struct{}) }
func (c *Coordinator) Acquire(ctx context.Context) (Resource, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		if c.state.Closed || c.ctx.Err() != nil {
			c.mu.Unlock()
			return nil, ErrClosed
		}
		r := c.active
		if r != nil {
			select {
			case <-r.Done():
				r = nil
			default:
			}
		}
		if r != nil {
			c.mu.Unlock()
			return r, nil
		}
		ch := c.changed
		c.mu.Unlock()
		select {
		case c.wake <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ch:
		}
	}
}
func (c *Coordinator) Snapshot() Snapshot { c.mu.Lock(); defer c.mu.Unlock(); return c.state }

// ReportDegraded asks for a make-before-break alternative: while a healthy
// resource serves traffic, the next eligible candidate is built and verified
// in the background; on success the active resource is swapped and closed.
// Repeat calls are folded; a failed alternative keeps the active one serving.
func (c *Coordinator) ReportDegraded() {
	c.mu.Lock()
	if c.state.Closed || c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	c.degraded = true
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *Coordinator) Close() error {
	c.mu.Lock()
	if c.state.Closed {
		c.mu.Unlock()
		return nil
	}
	c.state.Closed = true
	c.state.Generation++
	c.cancel()
	c.cancelGeneration()
	r := c.active
	c.active = nil
	c.state.ActiveID = ""
	c.signal()
	c.mu.Unlock()
	if r != nil {
		return r.Close()
	}
	return nil
}

// ResetNetwork invalidates borrowed resources and pending attempts without resetting fairness.
func (c *Coordinator) ResetNetwork() {
	c.mu.Lock()
	if c.state.Closed {
		c.mu.Unlock()
		return
	}
	c.cancelGeneration()
	c.generation, c.cancelGeneration = context.WithCancel(c.ctx)
	c.state.Generation++
	r := c.active
	c.active = nil
	c.state.ActiveID = ""
	c.signal()
	c.mu.Unlock()
	if r != nil {
		_ = r.Close()
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// prewarm builds and verifies one alternative candidate while current keeps
// serving. It consumes the next fair slot (skipping the current ID) and never
// touches the active resource or the snapshot. Best effort: any failure is a
// miss, not an error surfaced to callers.
func (c *Coordinator) prewarm(generation context.Context, current Resource) (Resource, string, bool) {
	c.mu.Lock()
	var candidate Candidate
	for range c.cfg.Candidates {
		v := c.cfg.Candidates[c.next]
		c.next = (c.next + 1) % len(c.cfg.Candidates)
		if c.active == nil || v.ID != c.state.ActiveID {
			candidate = v
			break
		}
	}
	if c.state.Closed || generation.Err() != nil || isNilResource(current) && false {
		c.mu.Unlock()
		return nil, "", false
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(generation, c.cfg.AttemptTimeout)
	defer cancel()
	alt, err := c.attempt(ctx, candidate)
	if err != nil || isNilResource(alt) {
		return nil, "", false
	}
	select {
	case <-alt.Done():
		return nil, "", false
	default:
	}
	return alt, candidate.ID, true
}

// attempt permits only one callback worker, including across network resets.
// Callbacks must cooperate with cancellation for recovery to progress. A stuck
// callback stalls retries, not Close; Go cannot forcibly terminate callbacks.
// Resource.Close and Done must return promptly and be safe during Verify.
func (c *Coordinator) attempt(ctx context.Context, v Candidate) (Resource, error) {
	type result struct {
		r   Resource
		err error
	}
	out := make(chan result, 1)
	var ownership sync.Mutex
	var known Resource
	var closeOnce sync.Once
	cleanup := func() {
		ownership.Lock()
		defer ownership.Unlock()
		if !isNilResource(known) {
			closeOnce.Do(func() { _ = known.Close() })
		}
	}
	stop := context.AfterFunc(ctx, cleanup)
	defer stop()
	go func() {
		r, err := c.cfg.Connect(ctx, v)
		ownership.Lock()
		known = r
		ownership.Unlock()
		if err == nil && isNilResource(r) {
			err = errors.New("nil resource")
		}
		if err == nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else {
				err = c.cfg.Verify(ctx, v, r)
			}
		}
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			cleanup()
			r = nil
		}
		out <- result{r, err}
	}()
	select {
	case res := <-out:
		// Stop the timeout cleanup before transferring ownership to the run loop.
		if !stop() || ctx.Err() != nil {
			cleanup()
			return nil, ctx.Err()
		}
		return res.r, res.err
	case <-ctx.Done():
		cleanup()
		// Never start another callback until this worker exits, even after reset.
		select {
		case res := <-out:
			if res.r != nil {
				cleanup()
			}
		case <-c.ctx.Done():
			// The worker retains cleanup ownership when Connect eventually returns.
			return nil, c.ctx.Err()
		}
		return nil, ctx.Err()
	}
}
func (c *Coordinator) run() {
	select {
	case <-c.ctx.Done():
		return
	case <-c.wake:
	}
	delay := c.cfg.Backoff
	epoch := 0
	for {
		c.mu.Lock()
		if c.state.Closed || c.ctx.Err() != nil {
			c.mu.Unlock()
			return
		}
		g := c.generation
		gen := c.state.Generation
		v := c.cfg.Candidates[c.next]
		if c.preferred && c.state.LastGood != "" {
			for index, candidate := range c.cfg.Candidates {
				if candidate.ID == c.state.LastGood {
					v = candidate
					c.next = (index + 1) % len(c.cfg.Candidates)
					break
				}
			}
			c.preferred = false
		} else {
			c.preferred = false
			c.next = (c.next + 1) % len(c.cfg.Candidates)
		}
		c.state.Attempts++
		c.mu.Unlock()
		ctx, cancel := context.WithTimeout(g, c.cfg.AttemptTimeout)
		r, err := c.attempt(ctx, v)
		cancel()
		c.mu.Lock()
		stale := c.state.Closed || gen != c.state.Generation || g.Err() != nil
		if !stale && err == nil {
			select {
			case <-r.Done():
				err = errors.New("resource already dead")
			default:
			}
		}
		if !stale && err == nil {
			c.active = r
			c.state.ActiveID = v.ID
			c.state.LastGood = v.ID
			c.signal()
			c.mu.Unlock()
			delay = c.cfg.Backoff
			epoch = 0
		serveLoop:
			for {
				select {
				case <-r.Done():
					break serveLoop
				case <-g.Done():
					break serveLoop
				case <-c.wake:
				}
				c.mu.Lock()
				degraded := c.degraded
				c.degraded = false
				c.mu.Unlock()
				// Make-before-break: build and verify one alternative while the
				// healthy resource keeps serving. Rate-limited by Backoff.
				if degraded && c.ctx.Err() == nil && time.Since(c.lastPrewarm) >= c.cfg.Backoff {
					c.lastPrewarm = time.Now()
					if alt, altID, ok := c.prewarm(g, r); ok {
						c.mu.Lock()
						c.active = alt
						c.state.ActiveID = altID
						c.state.LastGood = altID
						c.signal()
						c.mu.Unlock()
						_ = r.Close()
						delay = c.cfg.Backoff
						epoch = 0
						r = alt
					}
				}
			}
			c.mu.Lock()
			if c.state.Generation == gen && c.active != nil {
				c.active = nil
				c.state.ActiveID = ""
				c.signal()
				c.mu.Unlock()
				_ = r.Close()
			} else {
				c.mu.Unlock()
			}
			continue
		}
		c.mu.Unlock()
		if r != nil {
			_ = r.Close()
		}
		if stale {
			epoch = 0
			delay = c.cfg.Backoff
			continue
		}
		epoch++
		if epoch < len(c.cfg.Candidates) {
			continue
		}
		epoch = 0
		d := delay
		if c.cfg.Jitter != nil {
			d = c.cfg.Jitter(d)
			if d < c.cfg.Backoff {
				d = c.cfg.Backoff
			}
			if d > c.cfg.MaxBackoff {
				d = c.cfg.MaxBackoff
			}
		}
		waitErr := c.cfg.Wait(g, d)
		if g.Err() != nil {
			epoch = 0
			delay = c.cfg.Backoff
			continue
		}
		if waitErr != nil {
			_ = c.Close()
			return
		}
		if delay > c.cfg.MaxBackoff/2 {
			delay = c.cfg.MaxBackoff
		} else {
			delay *= 2
		}
	}
}
