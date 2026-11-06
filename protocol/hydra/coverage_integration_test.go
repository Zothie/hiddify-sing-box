package hydra

// Coverage-driven post-connection sweep against REAL Rust hydra-servers.
//
// Every coverage probe dials its URL THROUGH the candidate's tunnel session
// (the proof.go session-dial pattern: tunnel.openSession, strict TLS, small
// GET, bounded). Per-candidate origin reachability is discriminated with the
// adaptiveOutboundDependencies.CoverageAddr seam — the same deps seam the
// proof TLS config and the dialer factory use: the "partial" candidate has
// half of the probe URLs redirected to a closed port, the other candidates
// keep the real httptest origins. Tunnel, TLS and HTTP stay on the production
// path; only the dial target is steered per candidate.
//
// Proven here:
//   - a partial-coverage candidate is accepted first (the "not worse than
//     best" bar passes on the first measurement) but is never finally kept
//     once a full-coverage candidate verifies;
//   - a candidate measuring below the acceptance bar (best - hysteresis) is
//     rejected and never promoted;
//   - the improvement-driven sweep runs full candidate epochs while they
//     improve and STOPS after the first full epoch without improvement —
//     attempts stay bounded and stable (no infinite prewarm churn);
//   - Snapshot reports CoveragePercent/CoverageTarget honestly.
//
// Skipped when the hydra-server binary is absent (HYDRA_SERVER_BIN overrides;
// the default points at the hydra-adaptive debug build).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

func coverageCandidate(id, addr string, pubkey [32]byte) option.HydraAdaptiveCandidateOptions {
	host, portText, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portText)
	return option.HydraAdaptiveCandidateOptions{
		ID:            id,
		Pubkey:        encodeB64(pubkey[:]),
		ServerOptions: option.ServerOptions{Server: host, ServerPort: uint16(port)},
	}
}

func urlPort(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(u.Port())
	return port
}

// coverageTestEnv builds two real rust servers, the proof origin and a
// four-origin HTTPS probe set trusted by one shared root pool.
func coverageTestEnv(t *testing.T) (proofOrigin string, probeURLs []string, roots *x509.CertPool) {
	t.Helper()
	origin, _ := startProofOrigin(t, 1024)
	proofOrigin = origin.URL
	roots = x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	for i := 0; i < 4; i++ {
		probe, _ := startProofOrigin(t, 1024)
		roots.AddCert(probe.Certificate())
		probeURLs = append(probeURLs, probe.URL)
	}
	return proofOrigin, probeURLs, roots
}

func coverageDeps(roots *x509.CertPool, steer func(candidateID string, port int) bool) adaptiveOutboundDependencies {
	return adaptiveOutboundDependencies{
		ProofTLS: &tls.Config{RootCAs: roots},
		DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
			return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
		},
		CoverageAddr: func(candidateID, host string, port int) string {
			if steer != nil && steer(candidateID, port) {
				return net.JoinHostPort("127.0.0.1", "1")
			}
			return ""
		},
	}
}

// waitForStableSweep polls until coordinator attempts stop growing for ~800ms
// (the improvement-driven sweep reached its stop condition) and returns the
// final snapshot.
func waitForStableSweep(t *testing.T, o *Outbound, wantActive []string) adaptive.Snapshot {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	stable := 0
	var last uint64
	for time.Now().Before(deadline) {
		snap := o.adaptiveSnapshot()
		activeOK := len(wantActive) == 0
		for _, id := range wantActive {
			if snap.ActiveID == id {
				activeOK = true
				break
			}
		}
		if snap.Attempts == last && snap.Attempts >= 2 && activeOK && snap.CoverageTarget > 0 {
			stable++
			if stable == 4 {
				return snap
			}
		} else {
			stable = 0
		}
		last = snap.Attempts
		time.Sleep(200 * time.Millisecond)
	}
	snap := o.adaptiveSnapshot()
	t.Fatalf("sweep never stabilized: attempts=%d active=%q coverage=%d/%d",
		snap.Attempts, snap.ActiveID, snap.CoveragePercent, snap.CoverageTarget)
	return snap
}

// TestCoverageFullBeatsPartial: the 50% candidate is accepted first (its
// measurement is the best seen so far), then the sweep — still below 100% —
// prewarms the 100% candidate and finally keeps it.
func TestCoverageFullBeatsPartial(t *testing.T) {
	addrPartial, pkPartial, _ := startRustServer(t)
	addrFull, pkFull, _ := startRustServer(t)
	proofOrigin, probeURLs, roots := coverageTestEnv(t)

	blocked := map[int]bool{}
	for i, u := range probeURLs {
		if i%2 == 0 {
			blocked[urlPort(u)] = true
		}
	}

	opts := option.HydraOutboundOptions{
		Pubkey: encodeB64(pkPartial[:]),
		Adaptive: &option.HydraAdaptiveOptions{
			Candidates: []option.HydraAdaptiveCandidateOptions{
				coverageCandidate("partial", addrPartial, pkPartial),
				coverageCandidate("full", addrFull, pkFull),
			},
			ProofURL:       proofOrigin,
			ProofBytes:     1024,
			AttemptTimeout: badoption.Duration(4 * time.Second),
			// Slow first backoff keeps the partial candidate visibly active
			// after the initial Acquire (the sweep driver ticks at this rate).
			Backoff:              badoption.Duration(2 * time.Second),
			MaxBackoff:           badoption.Duration(2 * time.Second),
			RecoveryBudget:       badoption.Duration(15 * time.Second),
			CoverageProbeURLs:    probeURLs,
			CoverageProbeTimeout: badoption.Duration(2 * time.Second),
		},
	}
	deps := coverageDeps(roots, func(candidateID string, port int) bool {
		return candidateID == "partial" && blocked[port]
	})
	a, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, log.NewNOPFactory().Logger(), "coverage-full-beats-partial", opts, deps)
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if _, err := o.getTunnel(ctx); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// First measurement 50% >= best 0: accepted, honest numbers reported.
	snap := o.adaptiveSnapshot()
	if snap.ActiveID != "partial" || snap.CoveragePercent != 50 || snap.CoverageTarget != 50 {
		t.Fatalf("after first acceptance: ActiveID=%q CoveragePercent=%d CoverageTarget=%d; want partial/50/50",
			snap.ActiveID, snap.CoveragePercent, snap.CoverageTarget)
	}
	// The sweep keeps going below 100%: the full-coverage candidate prewarms
	// in and finally replaces the partial one.
	deadline := time.Now().Add(30 * time.Second)
	for {
		snap = o.adaptiveSnapshot()
		if snap.ActiveID == "full" && snap.CoveragePercent == 100 && snap.CoverageTarget == 100 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("full-coverage candidate never took over: ActiveID=%q percent=%d target=%d",
				snap.ActiveID, snap.CoveragePercent, snap.CoverageTarget)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// At 100% coverage the sweep stops for good: attempts freeze.
	a1 := o.adaptiveSnapshot().Attempts
	time.Sleep(1500 * time.Millisecond)
	a2 := o.adaptiveSnapshot().Attempts
	if a1 != a2 {
		t.Fatalf("attempts still growing at 100%% coverage: %d -> %d", a1, a2)
	}
	t.Logf("partial accepted first, full took over after %d attempts", a2)
}

// TestCoverageSweepStopsWithoutImprovement: both candidates measure 50% (on
// different halves). The first full epoch improves best 0->50, the second
// improves nothing — the sweep must stop (no infinite epochs), keep a
// best-coverage candidate active and report 50/50 honestly.
func TestCoverageSweepStopsWithoutImprovement(t *testing.T) {
	addrA, pkA, _ := startRustServer(t)
	addrB, pkB, _ := startRustServer(t)
	proofOrigin, probeURLs, roots := coverageTestEnv(t)

	blockedA, blockedB := map[int]bool{}, map[int]bool{}
	for i, u := range probeURLs {
		if i%2 == 0 {
			blockedA[urlPort(u)] = true
		} else {
			blockedB[urlPort(u)] = true
		}
	}

	opts := option.HydraOutboundOptions{
		Pubkey: encodeB64(pkA[:]),
		Adaptive: &option.HydraAdaptiveOptions{
			Candidates: []option.HydraAdaptiveCandidateOptions{
				coverageCandidate("a", addrA, pkA),
				coverageCandidate("b", addrB, pkB),
			},
			ProofURL:             proofOrigin,
			ProofBytes:           1024,
			AttemptTimeout:       badoption.Duration(4 * time.Second),
			Backoff:              badoption.Duration(100 * time.Millisecond),
			MaxBackoff:           badoption.Duration(250 * time.Millisecond),
			RecoveryBudget:       badoption.Duration(12 * time.Second),
			CoverageProbeURLs:    probeURLs,
			CoverageProbeTimeout: badoption.Duration(2 * time.Second),
		},
	}
	deps := coverageDeps(roots, func(candidateID string, port int) bool {
		if candidateID == "a" {
			return blockedA[port]
		}
		return blockedB[port]
	})
	a, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, log.NewNOPFactory().Logger(), "coverage-stop-no-improvement", opts, deps)
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if _, err := o.getTunnel(ctx); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	snap := waitForStableSweep(t, o, []string{"a", "b"})
	if snap.CoveragePercent != 50 || snap.CoverageTarget != 50 {
		t.Fatalf("dishonest coverage report: percent=%d target=%d, want 50/50",
			snap.CoveragePercent, snap.CoverageTarget)
	}
	if snap.Attempts > 16 {
		t.Fatalf("unbounded epoch churn: attempts=%d", snap.Attempts)
	}
	t.Logf("sweep stopped after %d attempts, active=%s, coverage=%d/%d",
		snap.Attempts, snap.ActiveID, snap.CoveragePercent, snap.CoverageTarget)
}

// TestCoverageRejectsBelowBest: candidate c proves fine but covers 0% of the
// probe set while a covers 50%. The acceptance bar (best - hysteresis,
// hysteresis 0) rejects c: it must never be promoted, the partial candidate
// stays, and the sweep stops after the first epoch without improvement.
func TestCoverageRejectsBelowBest(t *testing.T) {
	addrA, pkA, _ := startRustServer(t)
	addrC, pkC, _ := startRustServer(t)
	proofOrigin, probeURLs, roots := coverageTestEnv(t)

	blockedA := map[int]bool{}
	for i, u := range probeURLs {
		if i%2 == 0 {
			blockedA[urlPort(u)] = true
		}
	}

	opts := option.HydraOutboundOptions{
		Pubkey: encodeB64(pkA[:]),
		Adaptive: &option.HydraAdaptiveOptions{
			Candidates: []option.HydraAdaptiveCandidateOptions{
				coverageCandidate("a", addrA, pkA),
				coverageCandidate("c", addrC, pkC),
			},
			ProofURL:             proofOrigin,
			ProofBytes:           1024,
			AttemptTimeout:       badoption.Duration(4 * time.Second),
			Backoff:              badoption.Duration(100 * time.Millisecond),
			MaxBackoff:           badoption.Duration(250 * time.Millisecond),
			RecoveryBudget:       badoption.Duration(12 * time.Second),
			CoverageProbeURLs:    probeURLs,
			CoverageProbeTimeout: badoption.Duration(2 * time.Second),
		},
	}
	deps := coverageDeps(roots, func(candidateID string, port int) bool {
		if candidateID == "a" {
			return blockedA[port]
		}
		return true // c: none of the probes answer
	})
	a, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, log.NewNOPFactory().Logger(), "coverage-reject-below-best", opts, deps)
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if _, err := o.getTunnel(ctx); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	snap := waitForStableSweep(t, o, []string{"a"})
	if snap.CoveragePercent != 50 || snap.CoverageTarget != 50 {
		t.Fatalf("dishonest coverage report: percent=%d target=%d, want 50/50",
			snap.CoveragePercent, snap.CoverageTarget)
	}
	if snap.Attempts < 2 {
		t.Fatalf("candidate c was never attempted: attempts=%d", snap.Attempts)
	}
	if snap.Attempts > 16 {
		t.Fatalf("unbounded epoch churn: attempts=%d", snap.Attempts)
	}
	t.Logf("c rejected, a kept after %d attempts, coverage=%d/%d",
		snap.Attempts, snap.CoveragePercent, snap.CoverageTarget)
}
