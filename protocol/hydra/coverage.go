package hydra

// Coverage-driven post-connection sweep.
//
// After the useful proof passes, a candidate's tunnel is asked to fetch an
// https origin set through its own session (the proof.go session-dial
// pattern: tunnel.openSession, strict TLS, small GET, bounded). The percent
// of URLs answering is the candidate's coverage. Acceptance keeps candidates
// within CoverageHysteresis points of the best coverage seen so far (default
// hysteresis 0: a candidate must not be worse), and while the active tunnel
// is below 100% the outbound keeps requesting make-before-break alternatives
// until coverage reaches 100% or a full candidate epoch stops improving.
// The best-coverage candidate is always the one kept.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
)

// CoverageProbeMaxURLs bounds one coverage probe set.
const CoverageProbeMaxURLs = 64

// Coverage probe timeout bounds; zero selects the default.
const (
	defaultCoverageTimeout = 5 * time.Second
	minCoverageTimeout     = 500 * time.Millisecond
	maxCoverageTimeout     = 60 * time.Second
)

// CoverageAddrOverride replaces the tunnel-dial target of one coverage probe
// (test seam; production leaves it nil). An empty result keeps the URL's own
// host:port. TLS identity always follows the URL host, never the override.
type CoverageAddrOverride func(candidateID, host string, port int) string

// parseCoverageURLs validates the https probe set (at most 64 entries).
func parseCoverageURLs(raw []string) ([]*url.URL, error) {
	if len(raw) > CoverageProbeMaxURLs {
		return nil, fmt.Errorf("hydra coverage: %d probe URLs exceed the limit of %d", len(raw), CoverageProbeMaxURLs)
	}
	out := make([]*url.URL, 0, len(raw))
	for _, r := range raw {
		u, err := url.Parse(r)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("hydra coverage: invalid HTTPS probe URL %q", r)
		}
		if u.Port() != "" {
			if _, err := net.LookupPort("tcp", u.Port()); err != nil {
				return nil, fmt.Errorf("hydra coverage: invalid probe port in %q", r)
			}
		}
		out = append(out, u)
	}
	return out, nil
}

// coverageRunner probes a verified tunnel against an https origin set and
// owns the acceptance state: the best coverage seen so far, per-candidate
// measurements, and the improvement-driven sweep stop condition.
type coverageRunner struct {
	urls         []*url.URL
	timeout      time.Duration
	hysteresis   int
	tlsCfg       *tls.Config
	addrOverride CoverageAddrOverride

	mu            sync.Mutex
	best          int
	measured      map[string]int
	slots         int // Measurements since the last epoch boundary.
	epochImproved bool
	stopped       bool
	candidates    int
}

func newCoverageRunner(urls []*url.URL, timeout time.Duration, hysteresis, candidates int, tlsCfg *tls.Config, override CoverageAddrOverride) (*coverageRunner, error) {
	if timeout == 0 {
		timeout = defaultCoverageTimeout
	}
	if timeout < minCoverageTimeout || timeout > maxCoverageTimeout {
		return nil, fmt.Errorf("hydra coverage: probe timeout outside %s..%s", minCoverageTimeout, maxCoverageTimeout)
	}
	if hysteresis < 0 || hysteresis > 100 {
		return nil, fmt.Errorf("hydra coverage: hysteresis outside 0..100")
	}
	if tlsCfg != nil && (tlsCfg.InsecureSkipVerify || tlsCfg.ServerName != "") {
		return nil, fmt.Errorf("hydra coverage: TLS identity overrides are forbidden")
	}
	return &coverageRunner{
		urls:         urls,
		timeout:      timeout,
		hysteresis:   hysteresis,
		tlsCfg:       tlsCfg,
		addrOverride: override,
		measured:     make(map[string]int),
		candidates:   candidates,
	}, nil
}

// verifyCoverage measures candidateID through tunnel and applies the
// acceptance bar: percent >= best - hysteresis; a new best always passes.
// The measurement is recorded before the verdict so the sweep's epoch
// accounting also sees rejected candidates.
func (r *coverageRunner) verifyCoverage(ctx context.Context, tunnel *Tunnel, candidateID string) error {
	answered := 0
	for _, u := range r.urls {
		if tunnel.IsDead() {
			break
		}
		if r.probeOne(ctx, tunnel, candidateID, u) {
			answered++
		}
	}
	percent := (answered*100 + len(r.urls)/2) / len(r.urls)
	if !r.record(candidateID, percent) {
		r.mu.Lock()
		best, hysteresis := r.best, r.hysteresis
		r.mu.Unlock()
		return fmt.Errorf("hydra coverage: candidate %q measured %d%%, below the acceptance bar (best %d%%, hysteresis %d%%)", candidateID, percent, best, hysteresis)
	}
	return nil
}

// probeOne fetches one origin through the tunnel: bounded, strict TLS
// (identity from the URL host even when the dial target is overridden),
// small GET, redirects not followed.
func (r *coverageRunner) probeOne(ctx context.Context, tunnel *Tunnel, candidateID string, u *url.URL) bool {
	pctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	portText := u.Port()
	if portText == "" {
		portText = "443"
	}
	addr := net.JoinHostPort(u.Hostname(), portText)
	if r.addrOverride != nil {
		port, _ := strconv.Atoi(portText)
		if v := r.addrOverride(candidateID, u.Hostname(), port); v != "" {
			addr = v
		}
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 8192,
		TLSClientConfig:        r.tlsCfg,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			portNum, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, err
			}
			return tunnel.openSession(dialCtx, host, uint16(portNum))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		Timeout:       r.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(pctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, _ = io.CopyN(io.Discard, response.Body, 4096)
	return response.StatusCode >= 200 && response.StatusCode < 400
}

// record stores a measurement and advances the sweep state. An epoch is
// candidates consecutive measurements (rejected candidates count — the
// scheduler keeps trying them, while the active candidate is never
// re-measured, so per-candidate counting would never complete). An epoch
// that raised the best starts a new one; an epoch that did not stops the
// sweep. Coverage 100% stops it immediately. Returns whether the candidate
// passes the acceptance bar.
func (r *coverageRunner) record(candidateID string, percent int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.measured[candidateID] = percent
	if percent > r.best {
		r.best = percent
		r.epochImproved = true
	}
	if r.best >= 100 {
		r.stopped = true
	}
	r.slots++
	if r.slots >= r.candidates {
		if r.epochImproved && r.best < 100 {
			r.slots = 0
			r.epochImproved = false
		} else {
			r.stopped = true
		}
	}
	return percent+r.hysteresis >= r.best
}

// report returns the active candidate's measured coverage and the best seen
// so far (the acceptance target). Both zero before the first measurement.
func (r *coverageRunner) report(activeID string) (percent, target int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.measured[activeID], r.best
}

func (r *coverageRunner) sweepStopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped
}

func (r *coverageRunner) bestCoverage() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.best
}

// reset clears all acceptance state (network identity change: the old best
// says nothing about the new network).
func (r *coverageRunner) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.best = 0
	r.measured = make(map[string]int)
	r.slots = 0
	r.epochImproved = false
	r.stopped = false
}

// driveCoverageSweep keeps requesting make-before-break alternatives while
// the best coverage is below 100% and epochs still improve — one
// ReportDegraded per interval, no more. Exits when the coordinator closes or
// ctx ends; once sweepStopped() is set it never probes again.
func driveCoverageSweep(ctx context.Context, coord *adaptive.Coordinator, r *coverageRunner, interval time.Duration) {
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if coord.Snapshot().Closed {
			return
		}
		if r.sweepStopped() || r.bestCoverage() >= 100 {
			continue
		}
		coord.ReportDegraded()
	}
}
