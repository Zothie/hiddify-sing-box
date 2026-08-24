package monitoring

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
)

const (
	defaultThroughputEveryNCycles = 4
	defaultThroughputTimeout      = 20 * time.Second
	defaultThroughputMaxJitter    = 5 * time.Second
	defaultThroughputStaleAfter   = 30 * time.Minute

	// Backoff bounds for an outbound that just failed to carry data. The
	// censor's per-flow penalty is reported to last on the order of 120s and to
	// be armed by repeated connection attempts, so retrying a failed node
	// quickly would both waste the probe and keep the penalty alive.
	throughputBackoffBase = 2 * time.Minute
	throughputBackoffMax  = 30 * time.Minute
)

// throughputProbe owns the bulk (sized-GET) probing policy.
//
// The probe answers the question the latency probe cannot: does this outbound
// actually move bytes? Running it is not free, and more importantly a burst of
// parallel bulk transfers is itself the pattern that provokes the censor's
// per-flow drop penalty. Building a detector that manufactures the very outage
// it is looking for would be worse than useless, so every probe here is:
//
//	serialized  - a global mutex, exactly one bulk transfer in flight per
//	              process, never a parallel fan-out across outbounds
//	jittered    - a random pre-probe delay, so probing has no fixed cadence
//	infrequent  - only once per EveryNCycles latency cycles
//	backed off  - a failed outbound is not retried for minutes, doubling
//
// Cheap latency probes are unaffected and keep running at full rate.
type throughputProbe struct {
	url             string
	bytes           int64
	minCarriedBytes int64
	everyNCycles    int
	timeout         time.Duration
	maxJitter       time.Duration
	staleAfter      time.Duration

	// gate serializes bulk transfers process-wide.
	gate sync.Mutex

	mu      sync.Mutex
	backoff map[string]*backoffState
}

type backoffState struct {
	until    time.Time
	duration time.Duration
}

func newThroughputProbe(options *option.ThroughputProbeOptions) *throughputProbe {
	if options == nil {
		return nil
	}
	p := &throughputProbe{
		url:             options.URL,
		bytes:           options.Bytes,
		minCarriedBytes: options.MinCarriedBytes,
		everyNCycles:    options.EveryNCycles,
		timeout:         options.Timeout.Build(),
		maxJitter:       options.MaxJitter.Build(),
		staleAfter:      options.StaleAfter.Build(),
		backoff:         make(map[string]*backoffState),
	}
	if p.url == "" {
		p.url = urltest.DefaultThroughputURL
	}
	if p.bytes <= 0 {
		p.bytes = urltest.DefaultThroughputBytes
	}
	if p.minCarriedBytes <= 0 {
		p.minCarriedBytes = urltest.DefaultMinCarriedBytes
	}
	if p.minCarriedBytes > p.bytes {
		// An unreachable pass mark would evict every outbound.
		p.minCarriedBytes = p.bytes
	}
	if p.everyNCycles <= 0 {
		p.everyNCycles = defaultThroughputEveryNCycles
	}
	if p.timeout <= 0 {
		p.timeout = defaultThroughputTimeout
	}
	if p.maxJitter <= 0 {
		p.maxJitter = defaultThroughputMaxJitter
	}
	if p.staleAfter <= 0 {
		p.staleAfter = defaultThroughputStaleAfter
	}
	return p
}

// dueForCycle reports whether this cycle should carry bulk probes.
func (p *throughputProbe) dueForCycle(cycleID uint64) bool {
	if p == nil {
		return false
	}
	return cycleID%uint64(p.everyNCycles) == 0
}

// suppressed reports whether tag is inside its failure backoff window.
func (p *throughputProbe) suppressed(tag string, now time.Time) bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.backoff[tag]
	return ok && now.Before(st.until)
}

// noteResult advances or clears the backoff for tag.
func (p *throughputProbe) noteResult(tag string, ok bool, now time.Time) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok {
		delete(p.backoff, tag)
		return
	}
	st := p.backoff[tag]
	if st == nil {
		st = &backoffState{duration: throughputBackoffBase}
	} else {
		st.duration *= 2
		if st.duration > throughputBackoffMax {
			st.duration = throughputBackoffMax
		}
	}
	st.until = now.Add(st.duration)
	p.backoff[tag] = st
}

// run performs one bulk probe, serialized process-wide and preceded by jitter.
// It returns the measured result and whether the outbound met the evidence bar.
func (p *throughputProbe) run(ctx context.Context, dialer adapter.Outbound) (urltest.ThroughputResult, bool, error) {
	var zero urltest.ThroughputResult
	if p == nil {
		return zero, false, nil
	}

	// Serialize before sleeping so queued probes spread out naturally instead
	// of all waking together.
	p.gate.Lock()
	defer p.gate.Unlock()

	if jitter := p.jitter(); jitter > 0 {
		timer := time.NewTimer(jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, false, ctx.Err()
		case <-timer.C:
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	result, err := urltest.URLTestThroughput(probeCtx, p.url, p.bytes, dialer)
	// The byte count is the verdict. A short read with no error is precisely
	// the frozen case and must fail, and an error that still moved enough bytes
	// is not a data-carrying failure.
	passed := result.CarriedBytes >= p.minCarriedBytes
	return result, passed, err
}

func (p *throughputProbe) jitter() time.Duration {
	if p.maxJitter <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(p.maxJitter)))
}
