package balancer

import (
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// throughputStaleAfter is how long a throughput verdict is believed. It must be
// comfortably longer than the bulk probe interval, or evidence would expire
// before it could be refreshed and every node would look unproven.
const throughputStaleAfter = 30 * time.Minute

// Throughput implements two-stage selection: first discard the outbounds that
// cannot demonstrably carry data, then rank the survivors by measured speed.
//
// WHY THIS EXISTS
// Every other strategy here ranks by latency, which under state censorship is
// both of the wrong things at once.
//
// It is the wrong liveness test. A censor's characteristic failure is a freeze,
// not a disconnect: the socket opens, TLS completes, and forwarding stops after
// roughly 16-20 KB. A latency probe -- a HEAD to a 204 endpoint that transfers
// no body -- returns instantly over such a path, so a dead node scores as the
// healthiest member of the group and the failover never fires. Only evidence of
// actual bytes delivered can tell these apart, which is what CarriedBytes is.
//
// It is also the wrong ranking. Latency measures proximity, not capacity, so a
// nearby relay at 3ms always outranks a distant exit at 25ms even when the
// distant one is many times faster. Users asking for "the best node" mean
// goodput. So survivors are ordered by measured KB/s, and latency is consulted
// only to break ties between nodes of equal measured speed.
//
// FAIL-OPEN
// If no outbound has proven itself -- typically at startup, before the slow
// bulk probe has run at all -- this deliberately falls back to latency ordering
// over the nodes that at least answered a ping, rather than dropping traffic.
// Absence of evidence is not evidence of a block, and an unproven path that
// might work beats a guaranteed outage.
type Throughput struct {
	outbounds map[string][]adapter.Outbound

	mu       sync.Mutex
	ranked   map[string][]adapter.Outbound
	selected map[string]adapter.Outbound
}

func NewThroughput(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *Throughput {
	couts := convertOutbounds(outbounds)
	s := &Throughput{
		outbounds: couts,
		ranked:    map[string][]adapter.Outbound{},
		selected:  map[string]adapter.Outbound{},
	}
	for _, net := range []string{N.NetworkTCP, N.NetworkUDP} {
		if len(couts[net]) > 0 {
			s.ranked[net] = couts[net]
			s.selected[net] = couts[net][0]
		}
	}
	return s
}

var _ Strategy = (*Throughput)(nil)

func (s *Throughput) Now() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if out, ok := s.selected[N.NetworkTCP]; ok && out != nil {
		return out.Tag()
	}
	return ""
}

// carriesData reports whether history proves this outbound moved real bytes
// recently. Unmeasured or stale evidence is not proof, and is handled by the
// caller's fail-open path rather than counted as a pass here.
func carriesData(his *adapter.URLTestHistory, now time.Time) bool {
	if !his.ThroughputMeasured() {
		return false
	}
	if now.Sub(his.ThroughputTime) > throughputStaleAfter {
		return false
	}
	return his.CarriedBytes > 0 && his.ThroughputKBps > 0
}

// rank performs the two stages for one network.
func rank(outs []adapter.Outbound, history map[string]*adapter.URLTestHistory, now time.Time) []adapter.Outbound {
	var proven []adapter.Outbound
	for _, out := range outs {
		if carriesData(history[out.Tag()], now) {
			proven = append(proven, out)
		}
	}

	if len(proven) > 0 {
		// Stage 2: fastest measured goodput first, latency as tie-break.
		sort.SliceStable(proven, func(i, j int) bool {
			hi := history[proven[i].Tag()]
			hj := history[proven[j].Tag()]
			if hi.ThroughputKBps != hj.ThroughputKBps {
				return hi.ThroughputKBps > hj.ThroughputKBps
			}
			return getTagDelay(proven[i].Tag(), history) < getTagDelay(proven[j].Tag(), history)
		})
		return proven
	}

	// Fail-open: nothing is proven yet. Prefer nodes that at least answered a
	// latency probe, ordered by delay. This is the pre-existing (weaker)
	// behaviour and is only reached before the first bulk probe completes, or
	// when every node genuinely failed -- in which case there is no good
	// choice and returning something is still better than returning nothing.
	var alive []adapter.Outbound
	for _, out := range outs {
		if getTagDelay(out.Tag(), history) < monitoring.TimeoutDelay {
			alive = append(alive, out)
		}
	}
	if len(alive) == 0 {
		alive = append(alive, outs...)
	}
	sort.SliceStable(alive, func(i, j int) bool {
		return getTagDelay(alive[i].Tag(), history) < getTagDelay(alive[j].Tag(), history)
	})
	return alive
}

func (s *Throughput) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	now := time.Now()
	newRanked := map[string][]adapter.Outbound{}
	newSelected := map[string]adapter.Outbound{}

	for net, outs := range s.outbounds {
		if len(outs) == 0 {
			continue
		}
		ordered := rank(outs, history, now)
		newRanked[net] = ordered
		if len(ordered) > 0 {
			newSelected[net] = ordered[0]
		}
	}

	s.mu.Lock()
	changed := false
	for net, out := range newSelected {
		prev, ok := s.selected[net]
		if !ok || prev == nil || prev.Tag() != out.Tag() {
			changed = true
		}
	}
	s.ranked = newRanked
	s.selected = newSelected
	s.mu.Unlock()

	return changed
}

func (s *Throughput) Select(metadata adapter.InboundContext, net string, touch bool) adapter.Outbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	if net != N.NetworkTCP && net != N.NetworkUDP {
		net = N.NetworkTCP
	}
	if out, ok := s.selected[net]; ok && out != nil {
		return out
	}
	if outs := s.outbounds[net]; len(outs) > 0 {
		return outs[0]
	}
	return nil
}
