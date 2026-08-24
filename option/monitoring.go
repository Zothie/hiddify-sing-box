package option

import "github.com/sagernet/sing/common/json/badoption"

type MonitoringOptions struct {
	Interval       badoption.Duration `json:"interval,omitempty"`
	URLs           []string           `json:"urls,omitempty"` //H
	Workers        int                `json:"workers,omitempty"`
	DebounceWindow badoption.Duration `json:"debounce_window,omitempty"`
	URLTestTimeout badoption.Duration `json:"url_test_timeout,omitempty"`
	IdleTimeout    badoption.Duration `json:"idle_timeout,omitempty"`

	// Bulk throughput probing. Off unless a group asks for it, because it costs
	// real user bandwidth and, done carelessly, is itself the traffic pattern
	// that provokes the censor it is meant to detect.
	Throughput *ThroughputProbeOptions `json:"throughput,omitempty"` //H
}

// ThroughputProbeOptions configures the sized-GET probe that decides whether an
// outbound can actually carry data, as opposed to merely answering a ping.
type ThroughputProbeOptions struct {
	// URL must serve a real body of at least Bytes. A /generate_204 endpoint
	// will not work: transferring nothing is what the plain latency probe
	// already does, and it is exactly why a frozen node looks healthy.
	URL string `json:"url,omitempty"`
	// Bytes to pull per probe. Must exceed the censor's freeze threshold
	// (~16-20 KB) or the probe cannot observe the failure it exists to find.
	Bytes int64 `json:"bytes,omitempty"`
	// MinCarriedBytes is the pass mark. Below this the outbound is treated as
	// unable to carry data, regardless of how fast it answered.
	MinCarriedBytes int64 `json:"min_carried_bytes,omitempty"`
	// EveryNCycles runs the bulk probe only once per N latency cycles. Bulk
	// transfers are costly and are reported to arm a per-flow drop penalty, so
	// this is intentionally infrequent.
	EveryNCycles int `json:"every_n_cycles,omitempty"`
	// Timeout for one bulk probe.
	Timeout badoption.Duration `json:"timeout,omitempty"`
	// MaxJitter bounds a random delay inserted before each probe, so probes do
	// not form a regular, fingerprintable cadence.
	MaxJitter badoption.Duration `json:"max_jitter,omitempty"`
	// StaleAfter is how long a throughput verdict stays trustworthy. Older
	// evidence is ignored rather than believed indefinitely.
	StaleAfter badoption.Duration `json:"stale_after,omitempty"`
}
