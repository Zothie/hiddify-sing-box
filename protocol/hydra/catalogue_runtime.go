package hydra

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// Catalogue-runtime hot swap (audit G2): the signed capability catalogue is
// fetched OUTSIDE the config build by the catalogue refresher
// (v2/hcore/hydra_control) and its expanded candidates are swapped into a
// LIVE adaptive outbound through this registry. The registry is keyed by the
// outbound tag (the merged adaptive group id, stable across profile
// refreshes) and binds each group to its relay pubkey — the same key
// material a catalogue server publishes and the CONFIRM frame authenticates
// against — so the refresher can match catalogue servers to live groups
// without new option surface.
//
// A swap target is registered when the adaptive outbound is constructed and
// replaced on re-construction (config reload). Outbound Close does NOT
// unregister eagerly (Close lives in outbound.go and must stay untouched);
// the first swap against a closed outbound unregisters lazily and fails.

// SwapTarget is one live adaptive outbound's catalogue binding.
type SwapTarget struct {
	// Tag is the outbound tag (the merged adaptive group id).
	Tag string
	// Pubkey is the group's relay pubkey, base64 (standard alphabet).
	// Catalogue candidates are matched to the group by this key.
	Pubkey string
	// ASN orders catalogue recipe expansion for this group (the asn= link
	// param via HydraAdaptiveOptions.CatalogueASN). Empty expands in
	// document order. Ordering hint only, never security.
	ASN string
	// AttemptTimeout and Budget are the group's live recovery timing: the
	// refresher expands with them so the budget check reflects what the
	// group will actually run.
	AttemptTimeout time.Duration
	Budget         time.Duration
	// Swap installs a validated candidate set into the live coordinator.
	Swap func([]option.HydraAdaptiveCandidateOptions) error

	// alive reports whether the owning outbound is still open. Discovery
	// prunes dead entries (Close lives in outbound.go and cannot unregister
	// eagerly); this keeps the refresher from erroring on stale tags.
	alive func() bool
}

var (
	swapMu       sync.RWMutex
	swapRegistry = make(map[string]SwapTarget)
)

// CatalogueSwapTargets returns a snapshot of the LIVE swap targets, pruning
// entries whose outbound has closed. The Swap funcs stay valid until their
// outbound is closed.
func CatalogueSwapTargets() []SwapTarget {
	swapMu.Lock()
	defer swapMu.Unlock()
	out := make([]SwapTarget, 0, len(swapRegistry))
	for tag, t := range swapRegistry {
		if t.alive != nil && !t.alive() {
			delete(swapRegistry, tag)
			continue
		}
		out = append(out, t)
	}
	return out
}

// SwapCatalogueCandidates installs candidates into the live adaptive
// outbound registered under tag. The outbound's own swap closure re-validates
// everything (identity, dedup, recovery budget) at the commit point; an
// unknown tag or a closed outbound is an error, never a silent skip.
func SwapCatalogueCandidates(tag string, candidates []option.HydraAdaptiveCandidateOptions) error {
	swapMu.RLock()
	t, ok := swapRegistry[tag]
	swapMu.RUnlock()
	if !ok {
		return fmt.Errorf("hydra: catalogue swap: no live adaptive outbound under tag %q", tag)
	}
	return t.Swap(candidates)
}

func registerCatalogueSwap(t SwapTarget) {
	swapMu.Lock()
	swapRegistry[t.Tag] = t
	swapMu.Unlock()
}

func unregisterCatalogueSwap(tag string) {
	swapMu.Lock()
	delete(swapRegistry, tag)
	swapMu.Unlock()
}

// BuildAdaptiveOutbound constructs the adaptive hydra outbound with the
// production dialer stack outside a box instance. The box registry path
// (NewOutbound) stays the production entry; this seam exists for the
// catalogue refresher's integration tests (and any host that composes
// outbounds directly). The registered swap target outlives the returned
// outbound only while the outbound is open.
func BuildAdaptiveOutbound(ctx context.Context, logger log.ContextLogger, tag string, options option.HydraOutboundOptions) (adapter.Outbound, error) {
	return newAdaptiveOutboundWithDependencies(ctx, nil, logger, tag, options, adaptiveOutboundDependencies{})
}

// OutboundDeps is the exported dependency seam of BuildAdaptiveOutboundWithDeps.
// Field-for-field identical to the internal dependency struct; tests use the
// standard dialer factory on hosts without a pinned physical interface.
type OutboundDeps struct {
	ProofTLS *tls.Config
	// DialerFactory overrides the per-candidate physical dialer. Nil uses
	// the production physical dialer (which requires an explicit interface).
	DialerFactory func(context.Context, option.HydraAdaptiveCandidateOptions) (N.Dialer, error)
	// ReferenceDialer overrides the blackout reference probe dialer.
	ReferenceDialer N.Dialer
	// CoverageAddr overrides the tunnel-dial target of one coverage probe.
	CoverageAddr CoverageAddrOverride
}

// BuildAdaptiveOutboundWithDeps is BuildAdaptiveOutbound with explicit
// dependencies (dialer factory, proof TLS).
func BuildAdaptiveOutboundWithDeps(ctx context.Context, logger log.ContextLogger, tag string, options option.HydraOutboundOptions, deps OutboundDeps) (adapter.Outbound, error) {
	return newAdaptiveOutboundWithDependencies(ctx, nil, logger, tag, options, adaptiveOutboundDependencies(deps))
}
