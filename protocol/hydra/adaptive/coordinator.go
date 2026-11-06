// Package adaptive coordinates verified resources for a fixed, prevalidated candidate set.
package adaptive

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
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
	Candidates []Candidate
	LastGood   string
	// StateKey scopes validated policy/config and network. Recreate this
	// coordinator on identity changes; ResetNetwork removes the old hint.
	StatePath      string
	StateKey       string
	AttemptTimeout time.Duration
	Backoff        time.Duration
	MaxBackoff     time.Duration
	// BlackoutRecheck is the wait between blackout reference rechecks. Zero
	// uses BlackoutRecheckDefault; other values clamp into
	// [BlackoutRecheckMin, BlackoutRecheckMax]. One recheck is one bounded
	// probe, never a candidate sweep.
	BlackoutRecheck time.Duration
	Connect         func(context.Context, Candidate) (Resource, error)
	Verify          func(context.Context, Candidate, Resource) error
	// Recheck performs one bounded reachability probe while blackout is
	// active. Returning true clears blackout and resumes the candidate
	// sweep. Nil leaves blackout in place until SetBlackout(false) arrives
	// from outside.
	Recheck func(context.Context) bool
	// Jitter must return promptly. Its output is clamped to [Backoff, MaxBackoff].
	Jitter func(time.Duration) time.Duration
	// Wait must return on cancellation. Nil uses a context-aware timer.
	// A non-cancellation error closes the coordinator to prevent hot retries.
	Wait func(context.Context, time.Duration) error
}

type Snapshot struct {
	Generation            uint64
	ActiveID              string
	LastGood              string
	Attempts              uint64
	Closed                bool
	UniqueCandidatesTried uint64
	TotalAttempts         uint64        // Computed alias of Attempts.
	SearchElapsed         time.Duration // Cumulative active search, excluding healthy uptime.
	LastSearchElapsed     time.Duration // Most recently completed search interval.
	SearchInProgress      bool
	StateLoaded           bool
	StateSaved            bool
	StateError            string
	Blackout              bool   // Reference probes say the physical internet is dead.
	BlackoutReason        string // Why blackout was entered; empty when clear.
	CoveragePercent       int    // Measured percent of coverage probe URLs answered by the active tunnel; 0 = no coverage probing or nothing measured yet.
	CoverageTarget        int    // Best coverage observed so far — the bar a replacement candidate must match within hysteresis.
}

var ErrClosed = errors.New("adaptive coordinator closed")

// Blackout recheck doctrine: slow by default and clamped, so a blackout can
// never turn into a burst of probes.
const (
	BlackoutRecheckDefault = 60 * time.Second
	BlackoutRecheckMin     = 30 * time.Second
	BlackoutRecheckMax     = 10 * time.Minute
)

func clampBlackoutRecheck(d time.Duration) time.Duration {
	if d <= 0 {
		return BlackoutRecheckDefault
	}
	if d < BlackoutRecheckMin {
		return BlackoutRecheckMin
	}
	if d > BlackoutRecheckMax {
		return BlackoutRecheckMax
	}
	return d
}

// jittered widens a wait so concurrent clients never recheck in sync.
func jittered(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(max(int64(d)/8, 1)))*time.Nanosecond
}

// maxTrackedFailures caps the failure score so a long-dead candidate is only
// demoted, never permanently exiled from the fair rotation.
const maxTrackedFailures = 8

// pickScored returns the next candidate: fewest attempts first (fairness
// floor — every candidate is retried before any is retried twice), then
// fewest tracked failures (score priority), then config order. Deterministic
// by construction; no randomness, no starvation.
func (c *Coordinator) pickScored() Candidate {
	best := c.cfg.Candidates[0]
	bestAttempts, bestFailures := c.scoreOf(best.ID)
	for _, candidate := range c.cfg.Candidates[1:] {
		attempts, failures := c.scoreOf(candidate.ID)
		if attempts < bestAttempts || attempts == bestAttempts && failures < bestFailures {
			best, bestAttempts, bestFailures = candidate, attempts, failures
		}
	}
	return best
}

func (c *Coordinator) scoreOf(id string) (attempts, failures int) {
	if s, ok := c.stats[id]; ok {
		return s.attempts, s.failures
	}
	return 0, 0
}

func (c *Coordinator) stat(id string) *candStat {
	s, ok := c.stats[id]
	if !ok {
		s = &candStat{}
		c.stats[id] = s
	}
	return s
}

type candStat struct {
	attempts int
	failures int
}

func indexOfCandidate(candidates []Candidate, id string) int {
	for i, candidate := range candidates {
		if candidate.ID == id {
			return i
		}
	}
	return -1
}

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
	mu                 sync.Mutex
	cfg                Config
	ctx                context.Context
	cancel             context.CancelFunc
	generation         context.Context
	cancelGeneration   context.CancelFunc
	state              Snapshot
	active             Resource
	changed            chan struct{}
	wake               chan struct{}
	next               int
	preferred          bool
	degraded           bool
	lastPrewarm        time.Time
	stats              map[string]*candStat
	searchStarted      time.Time
	persistenceEnabled bool
	// blackoutCancel breaks the in-flight wait when blackout flips, so the
	// loop re-evaluates promptly instead of finishing the old interval.
	blackoutCancel context.CancelFunc
}

func New(parent context.Context, cfg Config) (*Coordinator, error) {
	if parent == nil || len(cfg.Candidates) == 0 || cfg.Connect == nil || cfg.Verify == nil || cfg.AttemptTimeout <= 0 || cfg.Backoff <= 0 || cfg.MaxBackoff < cfg.Backoff {
		return nil, errors.New("invalid adaptive configuration")
	}
	if (cfg.StatePath == "") != (cfg.StateKey == "") {
		return nil, errors.New("state path and key must be supplied together")
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
	cfg.BlackoutRecheck = clampBlackoutRecheck(cfg.BlackoutRecheck)
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
	c := &Coordinator{persistenceEnabled: true, cfg: cfg, ctx: ctx, cancel: cancel, generation: g, cancelGeneration: gcancel, changed: make(chan struct{}), wake: make(chan struct{}, 1), preferred: true, stats: make(map[string]*candStat), state: Snapshot{Generation: 1, LastGood: cfg.LastGood}}
	c.loadHint()
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
func (c *Coordinator) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.TotalAttempts = s.Attempts
	if s.SearchInProgress {
		s.SearchElapsed += time.Since(c.searchStarted)
	}
	return s
}

// All metric and promotion helpers require mu.
func (c *Coordinator) beginSearch() {
	if !c.state.SearchInProgress {
		c.searchStarted = time.Now()
		c.state.SearchInProgress = true
	}
}
func (c *Coordinator) endSearch() {
	if c.state.SearchInProgress {
		c.state.LastSearchElapsed = time.Since(c.searchStarted)
		c.state.SearchElapsed += c.state.LastSearchElapsed
		c.state.SearchInProgress = false
	}
}
func (c *Coordinator) countAttempt(id string) {
	c.beginSearch()
	if c.stat(id).attempts == 0 {
		c.state.UniqueCandidatesTried++
	}
	c.state.Attempts++
	c.stat(id).attempts++
}
func (c *Coordinator) promote(r Resource, id string) {
	c.active = r
	c.state.ActiveID = id
	c.state.LastGood = id
	// A verified tunnel is live proof the internet is not fully dead.
	c.state.Blackout = false
	c.state.BlackoutReason = ""
	c.endSearch()
	c.saveHint()
	c.signal()
}

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

// SetBlackout tells the coordinator whether the physical internet is
// reachable, as proven by the caller's reference probes. With blackout on,
// candidate attempts stop entirely; the loop then waits BlackoutRecheck with
// jitter and runs one bounded recheck per interval. Repeated identical calls
// only refresh the reason.
func (c *Coordinator) SetBlackout(on bool, reason string) {
	c.mu.Lock()
	if c.state.Closed || c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	if c.state.Blackout == on {
		if on {
			c.state.BlackoutReason = reason
		}
		c.mu.Unlock()
		return
	}
	c.state.Blackout = on
	if on {
		c.state.BlackoutReason = reason
		c.endSearch()
	} else {
		c.state.BlackoutReason = ""
	}
	cancel := c.blackoutCancel
	c.mu.Unlock()
	if cancel != nil {
		// Break any in-flight wait so the loop re-evaluates promptly.
		cancel()
	}
}

func (c *Coordinator) Close() error {
	c.mu.Lock()
	if c.state.Closed {
		c.mu.Unlock()
		return nil
	}
	c.endSearch()
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
	c.preferred = false
	c.degraded = false
	// A new physical network is unknown: let the sweep try again immediately.
	c.state.Blackout = false
	c.state.BlackoutReason = ""
	breakoutCancel := c.blackoutCancel
	c.blackoutCancel = nil
	c.state.LastGood = ""
	c.state.StateLoaded = false
	c.persistenceEnabled = false
	c.clearHint()
	c.stateError(errors.New("network changed; recreate coordinator with current network key to persist"))
	c.beginSearch()
	c.generation, c.cancelGeneration = context.WithCancel(c.ctx)
	c.state.Generation++
	r := c.active
	c.active = nil
	c.state.ActiveID = ""
	c.signal()
	c.mu.Unlock()
	if breakoutCancel != nil {
		breakoutCancel()
	}
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
// replaces the active resource itself. Attempts contribute to lifetime metrics.
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
	if c.state.Closed || generation.Err() != nil || isNilResource(current) || c.active != current || candidate.ID == "" {
		c.mu.Unlock()
		return nil, "", false
	}
	c.countAttempt(candidate.ID)
	c.mu.Unlock()
	succeeded := false
	defer func() {
		c.mu.Lock()
		if c.generation == generation {
			if succeeded {
				c.stat(candidate.ID).failures = 0
			} else {
				if c.stat(candidate.ID).failures < maxTrackedFailures {
					c.stat(candidate.ID).failures++
				}
				c.endSearch()
			}
		}
		c.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(generation, c.cfg.AttemptTimeout)
	defer cancel()
	alt, err := c.attempt(ctx, candidate)
	if err != nil || isNilResource(alt) {
		return nil, "", false
	}
	select {
	case <-alt.Done():
		_ = alt.Close()
		return nil, "", false
	default:
	}
	succeeded = true
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
		// Blackout: candidate attempts stop entirely. The loop waits
		// BlackoutRecheck with jitter, then runs ONE bounded reference
		// recheck; candidates resume only after a recheck succeeds.
		if c.state.Blackout {
			c.endSearch()
			recheck := c.cfg.BlackoutRecheck
			c.mu.Unlock()
			waitCtx, cancel := context.WithCancel(g)
			c.mu.Lock()
			c.blackoutCancel = cancel
			c.mu.Unlock()
			waitErr := c.cfg.Wait(waitCtx, jittered(recheck))
			c.mu.Lock()
			c.blackoutCancel = nil
			closed := c.state.Closed || c.ctx.Err() != nil
			blackout := c.state.Blackout
			c.mu.Unlock()
			waitCanceled := waitCtx.Err() != nil
			cancel()
			if closed {
				return
			}
			if g.Err() != nil {
				epoch = 0
				delay = c.cfg.Backoff
				continue
			}
			if waitErr != nil && !waitCanceled {
				_ = c.Close()
				return
			}
			if blackout && c.cfg.Recheck != nil && c.cfg.Recheck(g) {
				c.SetBlackout(false, "")
				epoch = 0
				delay = c.cfg.Backoff
			}
			continue
		}
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
			// UCB-lite priority with a fairness floor: among candidates the
			// scheduler has tried least often (round-robin aging), prefer the
			// ones that failed least; equal scores keep config order, so the
			// first-ever epoch follows the configured wss-first doctrine and
			// no candidate can starve.
			v = c.pickScored()
			if index := indexOfCandidate(c.cfg.Candidates, v.ID); index >= 0 {
				c.next = (index + 1) % len(c.cfg.Candidates)
			}
			c.preferred = false
		}
		c.countAttempt(v.ID)
		c.mu.Unlock()
		ctx, cancel := context.WithTimeout(g, c.cfg.AttemptTimeout)
		r, err := c.attempt(ctx, v)
		cancel()
		c.mu.Lock()
		stale := c.state.Closed || c.ctx.Err() != nil || gen != c.state.Generation || g.Err() != nil
		if !stale {
			if err == nil {
				c.stat(v.ID).failures = 0
			} else if c.stat(v.ID).failures < maxTrackedFailures {
				c.stat(v.ID).failures++
			}
		}
		if !stale && err == nil {
			select {
			case <-r.Done():
				err = errors.New("resource already dead")
			default:
			}
		}
		if !stale && err == nil {
			c.promote(r, v.ID)
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
				blackout := c.state.Blackout
				c.mu.Unlock()
				// Make-before-break: build and verify one alternative while the
				// healthy resource keeps serving. Rate-limited by Backoff.
				// Blackout stops candidate attempts, prewarms included.
				if degraded && !blackout && c.ctx.Err() == nil && time.Since(c.lastPrewarm) >= c.cfg.Backoff {
					c.lastPrewarm = time.Now()
					if alt, altID, ok := c.prewarm(g, r); ok {
						c.mu.Lock()
						dead := false
						select {
						case <-alt.Done():
							dead = true
						default:
						}
						if c.state.Closed || c.ctx.Err() != nil || g.Err() != nil || gen != c.state.Generation || c.active != r || dead {
							if gen == c.state.Generation {
								c.endSearch()
							}
							c.mu.Unlock()
							_ = alt.Close()
							continue
						}
						c.promote(alt, altID)
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
				c.beginSearch()
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
		// The wait is interruptible: a blackout flip breaks it so the loop
		// re-evaluates at the top instead of finishing the old interval.
		waitCtx, cancel := context.WithCancel(g)
		c.mu.Lock()
		c.blackoutCancel = cancel
		c.mu.Unlock()
		waitErr := c.cfg.Wait(waitCtx, d)
		c.mu.Lock()
		c.blackoutCancel = nil
		closed := c.state.Closed || c.ctx.Err() != nil
		c.mu.Unlock()
		waitCanceled := waitCtx.Err() != nil
		cancel()
		if closed {
			return
		}
		if g.Err() != nil {
			epoch = 0
			delay = c.cfg.Backoff
			continue
		}
		if waitErr != nil && !waitCanceled {
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
