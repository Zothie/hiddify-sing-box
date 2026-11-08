package hydra

import (
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Candidate tuning axes (TUNING.md sweep): the option fields carry the axes
// from a signed catalogue recipe or a hydra:// solo link; this file resolves
// them into the internal carrier (tunnelAxes) that threads through the
// tunnel/engine constructors. A zero option field activates nothing here —
// each consumer applies its own baseline (the ws split path: the Rust
// frag.rs tuning baseline; everything else: current behavior, audit F4).

// tunnelAxes is the per-candidate axis carrier threaded through the tunnel
// constructors (variadic, so legacy call sites keep compiling). The zero
// value is byte-identical to the pre-axes behavior.
type tunnelAxes struct {
	// pad configures frame padding on the ws path (sealCtrFor); nil = the
	// proto.rs default ladder. The rtc engine consumes the same candidate
	// buckets through padTargetWithConfig (rtc-axes drop).
	pad *padConfig
	// split carries the wss ClientHello fragmentation/disorder axes
	// (split.go SplitParams); applied by the transport dialer chain only.
	split SplitParams
	// rtc carries the rtc OPTION-level engine axes; rtc_tunnel converts them
	// onto the engine's RtcChannelParams (rtcChannelParams: zero option axes
	// stay zero struct fields, and RtcChannelParams.normalize() — idempotent,
	// zero = today's defaults — applies them at the engine).
	rtc rtcOptionAxes
	// dpiGate rides the rtc pump only: the embedded ClientSelfGate (100%
	// verdict parity) with its raise threshold. A disabled gate stays
	// ungated; the threshold is consumed verbatim when enabled (0 = the
	// deliberate raise-on-everything probe).
	dpiGateEnabled   bool
	dpiGateThreshold float32
}

// dpiGateDefaultThreshold is the Rust HYDRA_DPI_THRESHOLD default applied
// when a gate is enabled without an explicit threshold.
const dpiGateDefaultThreshold = 0.5

// rtcOptionAxes holds the rtc engine axes exactly as the option layer
// carries them (ms uint32s, zero = engine default).
type rtcOptionAxes struct {
	Chunk            uint32
	Window           uint32
	RtoMinMs         uint32
	RtoMaxMs         uint32
	BufferCap        uint32
	KeepaliveEveryMs uint32
}

// splitParamsFromOption maps the candidate/parent option fields onto the
// split.go axis struct. Zero fields stay zero: split.go normalized() applies
// the Rust frag.rs baseline (first 8..64, rest 16..96, 1ms pacing, disorder
// off / 10ms pace) and ALL clamps happen inside split.go — never here. A nil
// logger silences fallback-reason logging.
func splitParamsFromOption(firstMin, firstMax, restMin, restMax, splitDelayMs, disorderDelayMs uint32, disorder bool, logger log.ContextLogger) SplitParams {
	return SplitParams{
		FirstMin:        int(firstMin),
		FirstMax:        int(firstMax),
		RestMin:         int(restMin),
		RestMax:         int(restMax),
		SplitDelayMs:    int(splitDelayMs),
		Disorder:        disorder,
		DisorderDelayMs: int(disorderDelayMs),
		Logger:          logger,
	}
}

// resolvePadAxes validates and resolves the padding axes into a padConfig.
// pad_buckets is fail-closed (audit F10): a malformed ladder is an error,
// never a silent degrade. max_pad clamps to <=64 (proto.rs MAX_PAD) and
// big_pad_max to <=4096; zero values keep the defaults.
func resolvePadAxes(buckets []uint32, maxPadAxis, bigPadMaxAxis uint32) (*padConfig, error) {
	if err := validatePadBuckets(buckets); err != nil {
		return nil, err
	}
	if maxPadAxis > MaxPad {
		maxPadAxis = MaxPad
	}
	if bigPadMaxAxis > bigPadDefault {
		bigPadMaxAxis = bigPadDefault
	}
	return newPadConfig(buckets, maxPadAxis, bigPadMaxAxis), nil
}

// resolveCandidateAxes resolves every axis of one candidate/parent option
// set. Out-of-domain numeric axes clamp into their engine ranges (the same
// clamp semantics as the Rust engine's tuning getters); a malformed
// pad_buckets ladder fails construction (F10).
func resolveCandidateAxes(o option.HydraAdaptiveCandidateOptions, logger log.ContextLogger) (tunnelAxes, error) {
	axes := tunnelAxes{}
	// tls_fingerprint is fail-closed: an unknown uTLS fingerprint name is a
	// construction error, never a silent fall back to plain TLS (the whole
	// point of the axis is the on-wire ClientHello shape).
	if err := validateTLSFingerprint(o.TLSFingerprint); err != nil {
		return axes, err
	}
	pad, err := resolvePadAxes(o.PadBuckets, o.MaxPad, o.BigPadMax)
	if err != nil {
		return axes, err
	}
	axes.pad = pad
	axes.split = splitParamsFromOption(o.FragFirstMin, o.FragFirstMax, o.FragRestMin, o.FragRestMax,
		o.FragSplitDelayMs, o.DisorderDelayMs, o.Disorder, logger)
	axes.rtc = rtcOptionAxes{
		Chunk:            o.RTCChunk,
		Window:           o.RTCWindow,
		RtoMinMs:         o.RTORtoMinMs,
		RtoMaxMs:         o.RTORtoMaxMs,
		BufferCap:        o.RTCBufferCap,
		KeepaliveEveryMs: o.RTCKeepaliveEveryMs,
	}
	axes.dpiGateEnabled = o.DPIGateEnabled
	// An enabled gate consumes its threshold VERBATIM (0 = deliberate
	// raise-on-everything); a disabled gate bakes the Rust default so the
	// value in the identity JSON stays concrete.
	axes.dpiGateThreshold = dpiGateDefaultThreshold
	if o.DPIGateEnabled {
		axes.dpiGateThreshold = o.DPIGateThreshold
	}
	return axes, nil
}

// axesOrDefault resolves the axes with parent fallback: a candidate axis
// left at zero inherits the parent (solo-link / group default) value, so a
// plain link can tune its static outbound while grouped candidates keep
// per-recipe values. The RESULT feeds both the child outbound and the
// effective-options identity, keeping inherited aliases collapsed (an alias
// carrying zero axes on a tuned parent resolves to the same effective
// configuration as the tuned original).
func axesOrDefault(candidate, parent option.HydraAdaptiveCandidateOptions, logger log.ContextLogger) (option.HydraAdaptiveCandidateOptions, tunnelAxes, error) {
	merged := candidate
	if merged.FragFirstMin == 0 {
		merged.FragFirstMin = parent.FragFirstMin
	}
	if merged.FragFirstMax == 0 {
		merged.FragFirstMax = parent.FragFirstMax
	}
	if merged.FragRestMin == 0 {
		merged.FragRestMin = parent.FragRestMin
	}
	if merged.FragRestMax == 0 {
		merged.FragRestMax = parent.FragRestMax
	}
	if merged.FragSplitDelayMs == 0 {
		merged.FragSplitDelayMs = parent.FragSplitDelayMs
	}
	if !merged.Disorder {
		merged.Disorder = parent.Disorder
	}
	if merged.DisorderDelayMs == 0 {
		merged.DisorderDelayMs = parent.DisorderDelayMs
	}
	if len(merged.PadBuckets) == 0 {
		merged.PadBuckets = parent.PadBuckets
	}
	if merged.MaxPad == 0 {
		merged.MaxPad = parent.MaxPad
	}
	if merged.BigPadMax == 0 {
		merged.BigPadMax = parent.BigPadMax
	}
	if merged.RTCChunk == 0 {
		merged.RTCChunk = parent.RTCChunk
	}
	if merged.RTCWindow == 0 {
		merged.RTCWindow = parent.RTCWindow
	}
	if merged.RTORtoMinMs == 0 {
		merged.RTORtoMinMs = parent.RTORtoMinMs
	}
	if merged.RTORtoMaxMs == 0 {
		merged.RTORtoMaxMs = parent.RTORtoMaxMs
	}
	if merged.RTCBufferCap == 0 {
		merged.RTCBufferCap = parent.RTCBufferCap
	}
	if merged.RTCKeepaliveEveryMs == 0 {
		merged.RTCKeepaliveEveryMs = parent.RTCKeepaliveEveryMs
	}
	if !merged.DPIGateEnabled && parent.DPIGateEnabled {
		merged.DPIGateEnabled = true
		merged.DPIGateThreshold = parent.DPIGateThreshold
	}
	if !merged.TLSFragment {
		merged.TLSFragment = parent.TLSFragment
	}
	if merged.TLSMinVersion == "" {
		merged.TLSMinVersion = parent.TLSMinVersion
	}
	if merged.TLSMaxVersion == "" {
		merged.TLSMaxVersion = parent.TLSMaxVersion
	}
	if len(merged.TLSALPN) == 0 {
		merged.TLSALPN = parent.TLSALPN
	}
	if merged.TLSFingerprint == "" {
		merged.TLSFingerprint = parent.TLSFingerprint
	}
	if merged.HandshakeSpacingMs == 0 {
		merged.HandshakeSpacingMs = parent.HandshakeSpacingMs
	}
	axes, err := resolveCandidateAxes(merged, logger)
	return merged, axes, err
}

// rtcChannelParams converts the option-level rtc + pad axes onto the
// engine's RtcChannelParams (normalize() is zero = defaults, idempotent).
// The pad axes come from the resolved padConfig, whose maxPad/bigPadMax are
// always >= 1 — never the rtc engine's literal-0 zero-pad mode, which no
// option value can produce (audit reconciliation: the ws site keeps
// crypto.go's own pad path, the rtc site consumes these fields).
func rtcChannelParams(ax tunnelAxes) RtcChannelParams {
	p := RtcChannelParams{}
	if ax.rtc.Chunk > 0 {
		p.Chunk = int(ax.rtc.Chunk)
	}
	if ax.rtc.Window > 0 {
		p.Window = int(ax.rtc.Window)
	}
	if ax.rtc.RtoMinMs > 0 {
		p.RtoMinMs = float64(ax.rtc.RtoMinMs)
	}
	if ax.rtc.RtoMaxMs > 0 {
		p.RtoMaxMs = float64(ax.rtc.RtoMaxMs)
	}
	if ax.rtc.BufferCap > 0 {
		p.BufferCap = int(ax.rtc.BufferCap)
	}
	if ax.rtc.KeepaliveEveryMs > 0 {
		p.KeepaliveEvery = time.Duration(ax.rtc.KeepaliveEveryMs) * time.Millisecond
	}
	if ax.pad != nil {
		if len(ax.pad.buckets) > 0 {
			p.PadBuckets = append([]int(nil), ax.pad.buckets...)
		}
		if ax.pad.maxPad > 0 {
			p.MaxPad = ax.pad.maxPad
		}
		if ax.pad.bigPadMax > 0 {
			p.BigFramePadMax = ax.pad.bigPadMax
		}
	}
	return p
}

// hydraParentAxes views the parent (solo / group-default) axis passthrough
// fields of HydraOutboundOptions as a candidate axis set, so the static
// outbound resolves solo-link axes through the same code path as grouped
// candidates.
func hydraParentAxes(o option.HydraOutboundOptions) option.HydraAdaptiveCandidateOptions {
	return option.HydraAdaptiveCandidateOptions{
		FragFirstMin:        o.FragFirstMin,
		FragFirstMax:        o.FragFirstMax,
		FragRestMin:         o.FragRestMin,
		FragRestMax:         o.FragRestMax,
		FragSplitDelayMs:    o.FragSplitDelayMs,
		Disorder:            o.Disorder,
		DisorderDelayMs:     o.DisorderDelayMs,
		PadBuckets:          o.PadBuckets,
		MaxPad:              o.MaxPad,
		BigPadMax:           o.BigPadMax,
		RTCChunk:            o.RTCChunk,
		RTCWindow:           o.RTCWindow,
		RTORtoMinMs:         o.RTORtoMinMs,
		RTORtoMaxMs:         o.RTORtoMaxMs,
		RTCBufferCap:        o.RTCBufferCap,
		RTCKeepaliveEveryMs: o.RTCKeepaliveEveryMs,
		TLSFragment:         o.TLSFragment,
		TLSMinVersion:       o.TLSMinVersion,
		TLSMaxVersion:       o.TLSMaxVersion,
		TLSALPN:             o.TLSALPN,
		DPIGateEnabled:      o.DPIGateEnabled,
		DPIGateThreshold:    o.DPIGateThreshold,
	}
}
