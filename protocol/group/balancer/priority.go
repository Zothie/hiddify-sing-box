package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// Priority walks the outbound list in the order the user wrote it and picks the
// first one that is currently reachable.
//
// WHY THIS EXISTS
// The existing strategies all answer "which node is fastest", which is the wrong
// question under state censorship. A nearby relay always wins on latency, so
// lowest-delay pins traffic to it even while a censor is throttling it to
// uselessness, and round-robin keeps feeding a share of every request into
// whichever node is currently blocked. Users express their real preference as an
// ORDER — try the direct path first, fall back to the relay, fall back to the
// slow-but-unblockable one — and no existing strategy expresses that.
//
// So: order is preference, and delay is used only as a liveness signal. A node
// is skipped when its probe timed out; otherwise the earliest listed node wins,
// regardless of how much faster a later one is.
//
// If every node looks dead we keep the first one rather than dropping traffic:
// the probe may be lying (it can time out while the path still carries data),
// and returning something the caller can try beats returning nothing.
type Priority struct {
	outbounds        map[string][]adapter.Outbound
	selectedOutbound map[string]adapter.Outbound

	mu sync.Mutex
}

func NewPriority(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *Priority {
	couts := convertOutbounds(outbounds)
	// Guard the empty case: a group with no members for a network would panic
	// on index [0] at Start. Inherited from lowest_delay.go, but Throughput
	// already guards it — keep the two consistent.
	sel := map[string]adapter.Outbound{}
	for _, net := range []string{N.NetworkTCP, N.NetworkUDP} {
		if len(couts[net]) > 0 {
			sel[net] = couts[net][0]
		}
	}
	return &Priority{
		outbounds:        couts,
		selectedOutbound: sel,
	}
}

var _ Strategy = (*Priority)(nil)

func (s *Priority) Now() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// An empty group has no selection; report that rather than dereferencing nil.
	if out, ok := s.selectedOutbound[N.NetworkTCP]; ok && out != nil {
		return out.Tag()
	}
	return ""
}

// firstAlive returns the earliest-listed outbound whose last probe did not time
// out, falling back to the first entry when none qualify.
func firstAlive(outs []adapter.Outbound, history map[string]*adapter.URLTestHistory) adapter.Outbound {
	if len(outs) == 0 {
		return nil
	}
	for _, out := range outs {
		if getTagDelay(out.Tag(), history) < monitoring.TimeoutDelay {
			return out
		}
	}
	// Everything looks dead. Prefer the user's first choice over nothing: a
	// timed-out probe does not prove the path cannot carry traffic.
	return outs[0]
}

func (s *Priority) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	chosen := map[string]adapter.Outbound{}
	for net, outs := range s.outbounds {
		if out := firstAlive(outs, history); out != nil {
			chosen[net] = out
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	changed := false
	for net, out := range chosen {
		if cur, ok := s.selectedOutbound[net]; !ok || cur.Tag() != out.Tag() {
			changed = true
		}
		s.selectedOutbound[net] = out
	}
	return changed
}

func (s *Priority) Select(metadata adapter.InboundContext, net string, touch bool) adapter.Outbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	if net != N.NetworkTCP && net != N.NetworkUDP {
		net = N.NetworkTCP
	}
	return s.selectedOutbound[net]
}
