package hydra

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func newAdaptiveOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HydraOutboundOptions) (adapter.Outbound, error) {
	return newAdaptiveOutboundWithDependencies(ctx, router, logger, tag, options, adaptiveOutboundDependencies{})
}

type adaptiveOutboundDependencies struct {
	ProofTLS      *tls.Config
	DialerFactory func(context.Context, option.HydraAdaptiveCandidateOptions) (N.Dialer, error)
	// ReferenceDialer overrides the dialer used for blackout reference
	// probes (tests). Production builds one lazily from the candidate
	// factory, so probes share the candidates' physical binding.
	ReferenceDialer N.Dialer
	// CoverageAddr overrides the tunnel-dial target of one coverage probe
	// (tests). An empty result keeps the probe URL's own host:port; TLS
	// identity always follows the URL host, never the override.
	CoverageAddr CoverageAddrOverride
}

func newAdaptiveOutboundWithDependencies(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HydraOutboundOptions, deps adaptiveOutboundDependencies) (adapter.Outbound, error) {
	var proofTLS *tls.Config
	if deps.ProofTLS != nil {
		proofTLS = deps.ProofTLS.Clone()
		if proofTLS.RootCAs != nil {
			proofTLS.RootCAs = proofTLS.RootCAs.Clone()
		}
		if proofTLS.ClientCAs != nil {
			proofTLS.ClientCAs = proofTLS.ClientCAs.Clone()
		}
	}
	factory := deps.DialerFactory
	if factory == nil {
		factory = func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
			return newAdaptivePhysicalDialer(ctx, options.Adaptive, v)
		}
	}
	a := options.Adaptive
	if a == nil {
		return nil, fmt.Errorf("hydra: adaptive options required")
	}
	if options.Detour != "" || len(a.Candidates) == 0 || len(a.Candidates) > 64 {
		return nil, fmt.Errorf("hydra: invalid adaptive candidates or parent detour")
	}
	u, err := url.Parse(a.ProofURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || a.ProofBytes < 1024 || a.ProofBytes > 1048576 {
		return nil, fmt.Errorf("hydra: invalid HTTPS proof target")
	}
	if u.Port() != "" {
		if _, err = net.LookupPort("tcp", u.Port()); err != nil {
			return nil, fmt.Errorf("hydra: invalid proof port")
		}
	}
	attempt, backoff, max := time.Duration(a.AttemptTimeout), time.Duration(a.Backoff), time.Duration(a.MaxBackoff)
	if attempt == 0 {
		attempt = 10 * time.Second
	}
	if backoff == 0 {
		backoff = time.Second
	}
	if max == 0 {
		max = 30 * time.Second
	}
	if attempt < 100*time.Millisecond || attempt > time.Minute || backoff < 10*time.Millisecond || backoff > time.Minute || max < backoff || max > 5*time.Minute {
		return nil, fmt.Errorf("hydra: invalid adaptive timing")
	}
	budget := time.Duration(a.RecoveryBudget)
	if budget == 0 {
		budget = 30 * time.Second
	}
	if budget < 5*time.Second || budget > 5*time.Minute {
		return nil, fmt.Errorf("hydra: invalid recovery budget")
	}
	// One lost-tunnel recovery epoch must fit the budget: every candidate
	// gets one AttemptTimeout-bounded attempt per epoch, so a working
	// candidate anywhere in the first epoch order is verified in budget.
	if attempt*time.Duration(len(a.Candidates)) > budget {
		return nil, fmt.Errorf("hydra: recovery budget: %d candidates x %s exceeds %s", len(a.Candidates), attempt, budget)
	}
	referenceURLs := a.ReferenceURLs
	if len(referenceURLs) > blackoutMaxReferences {
		return nil, fmt.Errorf("hydra: too many blackout reference URLs")
	}
	for _, raw := range referenceURLs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("hydra: invalid blackout reference URL")
		}
		if strings.HasSuffix(u.Hostname(), ".onion") {
			return nil, fmt.Errorf("hydra: onion reference cannot resolve without DNS")
		}
		if u.Port() != "" {
			if _, err = net.LookupPort("tcp", u.Port()); err != nil {
				return nil, fmt.Errorf("hydra: invalid reference port")
			}
		}
	}
	blackoutRecheck := time.Duration(a.BlackoutRecheck)
	if blackoutRecheck == 0 {
		blackoutRecheck = adaptive.BlackoutRecheckDefault
	}
	if blackoutRecheck < adaptive.BlackoutRecheckMin || blackoutRecheck > adaptive.BlackoutRecheckMax {
		return nil, fmt.Errorf("hydra: invalid blackout recheck")
	}
	// The same TLS trust serves the reference probes; identity overrides
	// would let a dead-network verdict ride on an unauthenticated origin.
	if len(referenceURLs) > 0 && proofTLS != nil && (proofTLS.InsecureSkipVerify || proofTLS.ServerName != "") {
		return nil, fmt.Errorf("hydra: blackout reference TLS identity overrides are forbidden")
	}
	// Coverage sweep state: per-candidate https probe set sharing the proof
	// TLS trust (identity overrides forbidden for the same reason).
	var coverage *coverageRunner
	if len(a.CoverageProbeURLs) > 0 {
		probeURLs, err := parseCoverageURLs(a.CoverageProbeURLs)
		if err != nil {
			return nil, err
		}
		coverage, err = newCoverageRunner(probeURLs, time.Duration(a.CoverageProbeTimeout), a.CoverageHysteresis, len(a.Candidates), proofTLS, deps.CoverageAddr)
		if err != nil {
			return nil, err
		}
	}
	// Anti-salvo gate: every child handshake to the SAME host is spaced by
	// the candidate's handshake_spacing_ms axis (jittered). One gate per
	// adaptive outbound, so coordinator epochs and prewarms queue behind
	// each other instead of bursting (solo outbounds are untouched).
	spacingGate := newSNIGate()
	candidates := make([]adaptive.Candidate, 0, len(a.Candidates))
	built := make(map[string]*Outbound)
	endpoints := make(map[string]bool)
	for _, v := range a.Candidates {
		resolved, e := resolveAdaptiveCandidate(options, logger, v)
		if e != nil {
			return nil, e
		}
		if built[v.ID] != nil || endpoints[resolved.identity] {
			return nil, fmt.Errorf("hydra: invalid candidate %q", v.ID)
		}
		child, e := buildResolvedCandidate(ctx, logger, tag, deps, factory, v, resolved, spacingGate)
		if e != nil {
			return nil, e
		}
		built[v.ID] = child
		endpoints[resolved.identity] = true
		candidates = append(candidates, adaptive.Candidate{ID: v.ID})
	}
	// Each candidate owns its transport. No candidate is dialed until Acquire.
	o := &Outbound{Adapter: built[a.Candidates[0].ID].Adapter, logger: logger}
	proofURL, proofBytes := a.ProofURL, a.ProofBytes
	var stateKey string
	if a.StatePath != "" {
		if strings.TrimSpace(a.NetworkKey) == "" {
			return nil, fmt.Errorf("hydra: adaptive state requires network_key")
		}
		scoped := options
		copyAdaptive := *a
		copyAdaptive.StatePath = ""
		scoped.Adaptive = &copyAdaptive
		encoded, err := json.Marshal(scoped)
		if err != nil {
			return nil, err
		}
		stateKey = fmt.Sprintf("%x", sha256.Sum256(encoded))
	}
	// Blackout detection lives here, not in the coordinator: the outbound
	// knows the physical dialer and classifies connect-stage failures. A
	// full epoch of handshake-less failures triggers one bounded reference
	// probe; all-fail means the internet itself is dead.
	var coordinator *adaptive.Coordinator
	var watcher *blackoutWatcher
	// childrenMu guards the candidate child pool against the catalogue hot
	// swap (audit G2): the coordinator's Connect reads the pool on the sweep
	// loop, the swap mutates it after commit. Construction never overlaps a
	// swap (the swap target is registered only after construction).
	var childrenMu sync.Mutex
	if len(referenceURLs) > 0 {
		watcher = newBlackoutWatcher(len(a.Candidates), referenceURLs, proofTLS,
			func(probeCtx context.Context) (N.Dialer, error) {
				if deps.ReferenceDialer != nil {
					return deps.ReferenceDialer, nil
				}
				return factory(probeCtx, a.Candidates[0])
			},
			func(on bool, reason string) {
				if coordinator != nil {
					coordinator.SetBlackout(on, reason)
				}
			})
	}
	c, err := adaptive.New(ctx, adaptive.Config{StatePath: a.StatePath, StateKey: stateKey, Candidates: candidates, AttemptTimeout: attempt, Backoff: backoff, MaxBackoff: max, BlackoutRecheck: blackoutRecheck,
		Connect: func(ctx context.Context, v adaptive.Candidate) (adaptive.Resource, error) {
			childrenMu.Lock()
			b := built[v.ID]
			childrenMu.Unlock()
			if b == nil {
				// A hot swap removed this candidate while its last attempt
				// was still queued; the coordinator treats the attempt as
				// failed and moves on.
				return nil, fmt.Errorf("hydra: adaptive candidate %q no longer in the pool", v.ID)
			}
			var resource adaptive.Resource
			var err error
			if b.rtcTransport {
				resource, err = connectTunnelRTC(ctx, func(c context.Context) (net.PacketConn, error) {
					return b.dialer.ListenPacket(c, b.serverAddr)
				}, b.pubkey[:], b.serverAddr.AddrPort(), logger, b.negotiateMaxFrame, b.axes)
			} else {
				resource, err = connectTunnelNegotiate(ctx, func(ctx context.Context) (net.Conn, error) {
					return b.dialer.DialContext(ctx, N.NetworkTCP, b.serverAddr)
				}, &b.requestURL, b.headers, b.pubkey[:], logger, b.negotiateMaxFrame, b.axes)
			}
			if err != nil {
				watcher.record(err)
				return nil, err
			}
			// A handshake proves the network is up; reset the dead-epoch count.
			watcher.reset()
			return resource, nil
		},
		Verify: func(ctx context.Context, v adaptive.Candidate, r adaptive.Resource) error {
			if err := verifyTunnelProof(ctx, r.(*Tunnel), proofTarget{URL: proofURL, Bytes: proofBytes, TLS: proofTLS}); err != nil {
				return err
			}
			if coverage == nil {
				return nil
			}
			// Acceptance bar: the useful proof passed; the candidate must
			// also match the best coverage seen so far within hysteresis.
			return coverage.verifyCoverage(ctx, r.(*Tunnel), v.ID)
		},
		Recheck: watcher.recheck,
	})
	if err != nil {
		return nil, err
	}
	coordinator = c
	o.adaptive = c
	// Catalogue-runtime hot swap (audit G2). The target goes live only after
	// the coordinator exists; a re-constructed outbound replaces the
	// previous entry for the same tag. The closure re-validates everything
	// at the commit point — identity resolution, dedup inside the final set
	// and the recovery budget (G5) — and fails closed: a rejected swap
	// leaves the current set untouched and serving.
	registerCatalogueSwap(SwapTarget{
		Tag:            tag,
		Pubkey:         options.Pubkey,
		ASN:            a.CatalogueASN,
		AttemptTimeout: attempt,
		Budget:         budget,
		alive: func() bool {
			o.mu.Lock()
			defer o.mu.Unlock()
			return !o.isClosed
		},
		Swap: func(next []option.HydraAdaptiveCandidateOptions) error {
			o.mu.Lock()
			closed := o.isClosed
			o.mu.Unlock()
			if closed {
				// Lazy unregister: Close lives in outbound.go and must stay
				// untouched; the first post-close swap cleans the registry.
				unregisterCatalogueSwap(tag)
				return fmt.Errorf("hydra: catalogue swap %q: outbound closed", tag)
			}
			if len(next) == 0 {
				return fmt.Errorf("hydra: catalogue swap %q: empty candidate set", tag)
			}
			if need := attempt * time.Duration(len(next)); need > budget {
				return fmt.Errorf("hydra: catalogue swap %q: %d candidates x %s exceeds recovery budget %s", tag, len(next), attempt, budget)
			}
			// Build the final set's children view OUTSIDE the pool lock:
			// the dialer factory is the slow part. Surviving ids reuse the
			// pooled child (and their stats/fairness history); new ids build
			// fresh children.
			final := make(map[string]*Outbound, len(next))
			identities := make(map[string]bool, len(next))
			for _, v := range next {
				resolved, rerr := resolveAdaptiveCandidate(options, logger, v)
				if rerr != nil {
					return fmt.Errorf("hydra: catalogue swap %q: %w", tag, rerr)
				}
				if identities[resolved.identity] {
					return fmt.Errorf("hydra: catalogue swap %q: candidate %q duplicates an effective configuration", tag, v.ID)
				}
				identities[resolved.identity] = true
				childrenMu.Lock()
				child := built[v.ID]
				childrenMu.Unlock()
				if child == nil {
					builtChild, berr := buildResolvedCandidate(ctx, logger, tag, deps, factory, v, resolved, spacingGate)
					if berr != nil {
						return fmt.Errorf("hydra: catalogue swap %q: %w", tag, berr)
					}
					child = builtChild
				}
				final[v.ID] = child
			}
			// Read the active id BEFORE taking the pool lock (Snapshot takes
			// the coordinator lock; the sweep loop's Connect takes the pool
			// lock without the coordinator lock, so the order avoids a
			// cycle). A promote landing in the remaining window is safe:
			// closing a child never closes its dialer, so even the active
			// tunnel keeps working; the exception just keeps the pool entry
			// available.
			active := c.Snapshot().ActiveID
			childrenMu.Lock()
			defer childrenMu.Unlock()
			ids := make([]adaptive.Candidate, 0, len(next))
			for _, v := range next {
				ids = append(ids, adaptive.Candidate{ID: v.ID})
			}
			if err := c.ReplaceCandidates(ids); err != nil {
				return err
			}
			for id, child := range final {
				if built[id] == nil {
					built[id] = child
				}
			}
			// Amendment 4: bound the child pool — replaced children are
			// closed and dropped except the active tunnel's child (an
			// in-flight connect on a closed dialer fails naturally; a live
			// tunnel keeps serving). In Go a map entry can be deleted while
			// ranging.
			for id, child := range built {
				if _, keep := final[id]; !keep && id != active {
					_ = child.Close()
					delete(built, id)
				}
			}
			// Children share the parent's tag, and Outbound.Close
			// unregisters the ADAPTIVE registry under that tag — the prune
			// above would silently drop the PARENT's snapshot entry. Restore
			// it (the parent stays open; its entry must outlive this swap).
			adaptive.RegisterOutbound(tag, o.adaptiveSnapshot)
			// The blackout dead-epoch must mean a full epoch of the CURRENT
			// set, not the construction-time one.
			watcher.setEpochSize(len(next))
			return nil
		},
	})
	if coverage != nil {
		o.coverage = coverage
		// While the active tunnel is below full coverage, the sweep driver
		// keeps requesting make-before-break alternatives (rate-limited to
		// the coordinator backoff); it stops on its own once coverage is
		// 100% or a full epoch stops improving.
		go driveCoverageSweep(ctx, c, coverage, backoff)
	}
	adaptive.RegisterOutbound(tag, o.adaptiveSnapshot)
	return o, nil
}

// resolvedCandidate is one adaptive candidate's resolved construction
// material, shared by construction and the catalogue hot swap.
type resolvedCandidate struct {
	// identity is the effective-config JSON of the normalized candidate; it
	// must stay unique across a candidate set (two variants differing only
	// in one axis are distinct, an alias with zero axes on a tuned parent
	// collapses onto the parent).
	identity string
	pubkey   string
	maxFrame uint32
	tuned    option.HydraAdaptiveCandidateOptions
}

// resolveAdaptiveCandidate validates one adaptive candidate against the
// parent options and computes its effective identity. Construction and the
// catalogue hot swap share this path so a swapped candidate obeys every
// construction rule: pubkey/maxframe parent fallback, axes resolution with
// parent fallback (fail-closed on a malformed pad ladder, audit F10),
// transport/path normalization and host checks.
func resolveAdaptiveCandidate(options option.HydraOutboundOptions, logger log.ContextLogger, v option.HydraAdaptiveCandidateOptions) (resolvedCandidate, error) {
	var resolved resolvedCandidate
	resolved.pubkey, resolved.maxFrame = v.Pubkey, v.NegotiateMaxFrame
	if resolved.pubkey == "" {
		resolved.pubkey = options.Pubkey
	}
	if resolved.maxFrame == 0 && v.RecipeID == "" {
		resolved.maxFrame = options.NegotiateMaxFrame
	}
	tuned, _, axErr := axesOrDefault(v, hydraParentAxes(options), logger)
	if axErr != nil {
		return resolved, fmt.Errorf("hydra: candidate %q: %w", v.ID, axErr)
	}
	resolved.tuned = tuned
	host := strings.ToLower(strings.TrimSuffix(v.Server, "."))
	identity := tuned
	identity.ID = ""
	identity.RecipeID = ""
	identity.Pubkey = resolved.pubkey
	identity.NegotiateMaxFrame = resolved.maxFrame
	identity.Server = host
	identity.Transport = normalizeTransport(identity.Transport)
	if identity.Transport != transportWSS && identity.Transport != transportRTC {
		return resolved, fmt.Errorf("hydra: candidate %q: unknown transport %q", v.ID, v.Transport)
	}
	if identity.Path == "" {
		identity.Path = "/"
	} else if !strings.HasPrefix(identity.Path, "/") {
		identity.Path = "/" + identity.Path
	}
	encoded, marshalErr := json.Marshal(identity)
	if marshalErr != nil {
		return resolved, marshalErr
	}
	resolved.identity = string(encoded)
	if strings.TrimSpace(v.ID) == "" || host == "" || strings.ContainsAny(host, " /\\\t\n?#@") || v.ServerPort == 0 || v.Detour != "" {
		return resolved, fmt.Errorf("hydra: invalid candidate %q", v.ID)
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return resolved, fmt.Errorf("hydra: invalid server")
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return resolved, fmt.Errorf("hydra: invalid server")
				}
			}
		}
	}
	return resolved, nil
}

// buildResolvedCandidate builds the child outbound for an ALREADY-resolved
// candidate (resolveAdaptiveCandidate). Split from resolution so callers
// reject duplicate ids/identities BEFORE any dialer is built — a duplicate
// must not consume a dialer from the factory.
func buildResolvedCandidate(ctx context.Context, logger log.ContextLogger, tag string, deps adaptiveOutboundDependencies, factory func(context.Context, option.HydraAdaptiveCandidateOptions) (N.Dialer, error), v option.HydraAdaptiveCandidateOptions, resolved resolvedCandidate, spacingGate *sniGate) (*Outbound, error) {
	// TLS surface axes (tls_fragment / versions / alpn) are applied onto
	// a copy of the candidate TLS options; the resolved axis values live
	// on the child's own passthrough fields (single source of truth).
	tlsOptions := applyTLSAxes(v.TLS, resolved.tuned.TLSFragment, resolved.tuned.TLSMinVersion, resolved.tuned.TLSMaxVersion, resolved.tuned.TLSALPN, resolved.tuned.TLSFingerprint)
	base, e := factory(ctx, v)
	if e != nil {
		return nil, e
	}
	if base == nil {
		return nil, fmt.Errorf("hydra: nil candidate dialer")
	}
	t := resolved.tuned
	child, e := newStaticOutbound(ctx, logger, tag, option.HydraOutboundOptions{ServerOptions: v.ServerOptions, DialerOptions: v.DialerOptions, Pubkey: resolved.pubkey, Path: v.Path, TLS: tlsOptions, Transport: v.Transport, NegotiateMaxFrame: resolved.maxFrame, FragFirstMin: t.FragFirstMin, FragFirstMax: t.FragFirstMax, FragRestMin: t.FragRestMin, FragRestMax: t.FragRestMax, FragSplitDelayMs: t.FragSplitDelayMs, Disorder: t.Disorder, DisorderDelayMs: t.DisorderDelayMs, PadBuckets: t.PadBuckets, MaxPad: t.MaxPad, BigPadMax: t.BigPadMax, RTCChunk: t.RTCChunk, RTCWindow: t.RTCWindow, RTORtoMinMs: t.RTORtoMinMs, RTORtoMaxMs: t.RTORtoMaxMs, RTCBufferCap: t.RTCBufferCap, RTCKeepaliveEveryMs: t.RTCKeepaliveEveryMs, TLSFragment: t.TLSFragment, TLSMinVersion: t.TLSMinVersion, TLSMaxVersion: t.TLSMaxVersion, TLSALPN: t.TLSALPN, TLSFingerprint: t.TLSFingerprint, HandshakeSpacingMs: t.HandshakeSpacingMs, DPIGateEnabled: v.DPIGateEnabled, DPIGateThreshold: v.DPIGateThreshold}, base)
	if e != nil {
		return nil, e
	}
	out := child.(*Outbound)
	// Anti-salvo: gate the child's transport dialer (wss TCP dials AND rtc
	// packet sockets) behind the shared per-host spacing gate so coordinator
	// epochs and prewarms never burst handshakes at one host. Zero spacing
	// (the option-level clamp never produces it, but tests pass nil gates)
	// keeps the dialer untouched.
	if spacingGate != nil {
		host := strings.ToLower(strings.TrimSuffix(v.Server, "."))
		out.dialer = sniSpacingDialer{Dialer: out.dialer, gate: spacingGate, host: host,
			spacing: effectiveSpacing(host, t.HandshakeSpacingMs)}
	}
	return out, nil
}

func (o *Outbound) adaptiveSnapshot() adaptive.Snapshot {
	o.mu.Lock()
	c, cov := o.adaptive, o.coverage
	o.mu.Unlock()
	if c == nil {
		return adaptive.Snapshot{}
	}
	s := c.Snapshot()
	if cov != nil {
		s.CoveragePercent, s.CoverageTarget = cov.report(s.ActiveID)
	}
	return s
}
func (o *Outbound) resetAdaptiveNetwork() {
	o.mu.Lock()
	c, cov := o.adaptive, o.coverage
	closed := o.isClosed
	o.mu.Unlock()
	if c != nil && !closed {
		c.ResetNetwork()
	}
	// The old coverage best says nothing about the new network identity.
	if cov != nil && !closed {
		cov.reset()
	}
}

// Blackout probe doctrine (TSPU: bursty probes look like a dropping client
// and earn ~120s blackholes): probes are serial, jittered, small and rare —
// at most one HTTPS GET per reference per recheck interval.
const (
	blackoutMaxReferences = 3
	blackoutProbeTimeout  = 5 * time.Second
	blackoutProbeJitter   = 500 * time.Millisecond
)

// blackoutWatcher turns a full epoch of handshake-less candidate failures
// into ONE bounded reference probe and reports the verdict to the
// coordinator. The coordinator serializes Connect, so probes cannot overlap
// or burst; they are never counted as attempts and never serve user data.
type blackoutWatcher struct {
	mu          sync.Mutex
	epochSize   int
	consecutive int
	probing     bool
	urls        []string
	tlsConfig   *tls.Config
	dialerFor   func(context.Context) (N.Dialer, error)
	refDialer   N.Dialer
	setBlackout func(bool, string)
}

func newBlackoutWatcher(epochSize int, urls []string, tlsConfig *tls.Config, dialerFor func(context.Context) (N.Dialer, error), setBlackout func(bool, string)) *blackoutWatcher {
	return &blackoutWatcher{epochSize: epochSize, urls: append([]string(nil), urls...), tlsConfig: tlsConfig, dialerFor: dialerFor, setBlackout: setBlackout}
}

// isConnectStageFailure reports whether a candidate error means the attempt
// never reached a handshake: dial failures, DNS failures and timeouts.
// Handshake and auth failures prove the server is reachable, so they are
// never blackout evidence.
func isConnectStageFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return false
}

// record consumes one candidate Connect error. When a full dead epoch has
// accumulated, exactly one reference probe decides blackout — synchronously,
// so the next candidate attempt waits for the verdict instead of racing it.
func (w *blackoutWatcher) record(err error) {
	if w == nil {
		return
	}
	if !isConnectStageFailure(err) {
		w.reset()
		return
	}
	w.mu.Lock()
	w.consecutive++
	if w.consecutive < w.epochSize || w.probing {
		w.mu.Unlock()
		return
	}
	w.consecutive = 0
	w.probing = true
	w.mu.Unlock()
	ok, reason := w.probe(nil)
	w.mu.Lock()
	w.probing = false
	w.mu.Unlock()
	w.setBlackout(!ok, reason)
}

func (w *blackoutWatcher) reset() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.consecutive = 0
	w.mu.Unlock()
}

// setEpochSize updates the dead-epoch size after a candidate hot swap so a
// blackout probe still fires after exactly one full epoch of the CURRENT
// candidate set (a swap can grow or shrink it).
func (w *blackoutWatcher) setEpochSize(n int) {
	if w == nil || n <= 0 {
		return
	}
	w.mu.Lock()
	w.epochSize = n
	w.mu.Unlock()
}

// recheck is the coordinator's blackout hook: one bounded probe per interval.
func (w *blackoutWatcher) recheck(ctx context.Context) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	if w.probing {
		w.mu.Unlock()
		return false
	}
	w.probing = true
	w.mu.Unlock()
	ok, _ := w.probe(ctx)
	w.mu.Lock()
	w.probing = false
	w.mu.Unlock()
	return ok
}

func (w *blackoutWatcher) referenceDialer(ctx context.Context) (N.Dialer, error) {
	w.mu.Lock()
	d := w.refDialer
	w.mu.Unlock()
	if d != nil {
		return d, nil
	}
	d, err := w.dialerFor(ctx)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	if w.refDialer == nil {
		w.refDialer = d
	} else {
		d = w.refDialer
	}
	w.mu.Unlock()
	return d, nil
}

// probe runs one jittered HTTPS GET per reference through the physical
// dialer. Any completed HTTP response proves the internet is alive.
func (w *blackoutWatcher) probe(parent context.Context) (bool, string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if parent != nil {
		stop := context.AfterFunc(parent, cancel)
		defer stop()
	}
	dialer, err := w.referenceDialer(ctx)
	if err != nil {
		return false, fmt.Sprintf("reference dialer: %.200v", err)
	}
	// Jittered pre-delay: the probe stays uncorrelated with the sweep
	// cadence and with other clients rechecking at the same wall clock.
	select {
	case <-ctx.Done():
		return false, "reference probe canceled"
	case <-time.After(blackoutProbeJitter/2 + time.Duration(rand.Int64N(int64(blackoutProbeJitter/2)))):
	}
	tlsConfig := w.tlsConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 8192,
		DialTLSContext: func(dialCtx context.Context, _, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr(address))
			if err != nil {
				return nil, err
			}
			// A custom DialTLSContext bypasses the transport's automatic
			// identity fill; verify against the dialed hostname.
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil || host == "" {
				_ = conn.Close()
				return nil, fmt.Errorf("reference probe: bad TLS address %q", address)
			}
			probeTLS := tlsConfig.Clone()
			if probeTLS.ServerName == "" {
				probeTLS.ServerName = host
			}
			tlsConn := tls.Client(conn, probeTLS)
			if err := tlsConn.HandshakeContext(dialCtx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var failures []string
	for _, raw := range w.urls {
		if err := probeReference(ctx, client, raw); err != nil {
			failures = append(failures, fmt.Sprintf("%.160v", err))
			continue
		}
		return true, ""
	}
	reason := "reference probes failed: " + strings.Join(failures, "; ")
	if len(reason) > 480 {
		reason = reason[:480]
	}
	return false, reason
}

// probeReference performs the single bounded GET; any response counts.
func probeReference(ctx context.Context, client *http.Client, raw string) error {
	attemptCtx, cancel := context.WithTimeout(ctx, blackoutProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return err
}
