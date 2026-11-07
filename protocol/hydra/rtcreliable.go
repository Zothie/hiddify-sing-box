package hydra

// Ordered reliable datagram channel for the RTC transport — a Go port of the
// Rust reference (vpns/hydra src/reliable.rs), itself a light port of aivpn's
// fragment.rs (bounded reassembly) + fec.rs (parity repair).
//
// Design: stream bytes are cut into <=Chunk bodies; every body is sealed by
// the mask layer (the caller) at a per-kind counter base and sent as an
// SRTP-shaped packet. ACKs ride RTCP-RR-shaped packets (cumulative + 32-bit
// SACK bitmap); losses use RTO retransmission of the original sealed body.
// Legacy XOR parity is disabled: it omits shard lengths and can inject zeros
// into variable-length ciphertext streams. Reserved wire counters stay intact.
//
// The core is synchronous and unit-testable; the RtcMask engine (rtc.go) owns
// the wire glue.

import (
	"time"
)

// Stream bytes per data packet (wire: 12 RTP + 4 seq + Chunk + 16 tag <= 1190).
// Default value of RtcChannelParams.Chunk.
const Chunk = 1150

// Window is the default max unacked data packets in flight (backpressure
// window), i.e. the default value of RtcChannelParams.Window.
const Window = 128

// Wire-safe parameter ranges for RtcChannelParams, mirroring the Rust engine
// (vpns/hydra src/reliable.rs): the tuning getter validates the SPEC range
// 256..=1500 but the datagram budget caps the usable body (data wire =
// 12 RTP + 12 nonce + 4 seq + chunk + 16 tag; ingress bound wireBudget+64),
// so the engine clamps the effective chunk to 1180 — the same reliable.rs
// MAX_CHUNK semantics. Window 16..=1024 IS the engine range on both ends.
const (
	MinChunk  = 256
	MaxChunk  = 1180
	MinWindow = 16
	MaxWindow = 1024
)

// RtcChannelParams configures the RTC reliable data plane and survival axes
// (chunk + window + RTO bounds + buffer cap + keepalive cadence + frame pad
// shape). Zero fields mean current defaults (Chunk/Window 1150/128, RTO
// 250/3000 ms, buffer 512, keepalive 5 s, default pad buckets / 64 / 4096);
// out-of-range values are clamped into the wire-safe ranges, never rejected.
//
// BOTH-ENDS COUPLING — read before cataloguing an RTC variant (audit F5,
// corrected):
//
//   - The receiver is LENGTH-AGNOSTIC. Data bodies are [u32 seq][chunk of any
//     size] and reassembly runs by sequence number; the frame stream parses
//     its own lengths; padLen travels inside every sealed frame
//     ([padLen u16][pad][payload]). A chunk, window or pad mismatch between
//     peers does NOT break framing.
//   - The REAL bounds are numeric, not per-peer agreement: one data datagram
//     is 12 RTP + 12 nonce + 4 seq + chunk + 16 tag, so the chunk clamp of
//     1180 keeps the wire datagram at <=1224 bytes, under the ingress drop
//     limit of wireBudget+64 = 1284; and the SACK bitmap is 32 packets wide
//     (a window past 32 still works — recovery leans on cumulative ACKs).
//   - Matched chunk/window values are CATALOGUE POLICY — the server sizes its
//     own direction from HYDRA_RTC_CHUNK / HYDRA_RTC_WINDOW env (tuning.rs ->
//     ChannelParams::from_tuning; there is no in-band negotiation), so a
//     catalogued RTC candidate MUST declare the env values its server was
//     started with and the server MUST be launched with the values the client
//     config declares. This is an operator contract, not a protocol
//     requirement: there is deliberately no "must fail on mismatch" negative
//     test; TestRtcChunkWindowMismatchStillFrames pins the opposite.
//   - Window mismatch: each direction's window gates only its own sender
//     (a server keeps ITS window for server->client), so a mismatch merely
//     degrades throughput/backpressure symmetry; it cannot desync anything.
//   - Pad axes (buckets/MaxPad/BigFramePadMax) are one-sided: the peer strips
//     whatever padLen the frame declares. They change the observable frame
//     length histogram, nothing else.
type RtcChannelParams struct {
	// Chunk is the stream bytes per data packet. 0 = default (Chunk = 1150);
	// clamped to 256..=1180.
	Chunk int
	// Window is the max unacked data packets in flight. 0 = default
	// (Window = 128); clamped to 16..=1024.
	Window int
	// RtoMinMs is the retransmission-timeout floor in milliseconds (D1).
	// 0 = default (250); clamped to 50..=500.
	RtoMinMs float64
	// RtoMaxMs is the retransmission-timeout ceiling in milliseconds (D1).
	// 0 = default (3000); clamped to 1000..=10000. The two clamp ranges
	// guarantee RtoMin <= RtoMax after normalization for ANY input.
	RtoMaxMs float64
	// BufferCap is the per-direction out-of-order reassembly cap (D2).
	// 0 = default (512); clamped to 128..=2048.
	BufferCap int
	// KeepaliveEvery is the RTCP-SR + ICE consent cadence (D3). 0 = default
	// (5 s); clamped to 2..=15 s. The keepalive packet SHAPE is unchanged —
	// only the timer moves.
	KeepaliveEvery time.Duration
	// PadBuckets shapes the frame-length histogram the pad axis draws from.
	// nil/empty = default {256, 1024, 4096, 16384, 65536}; otherwise the set
	// must be strictly ascending, every value within 256..=65536 and at most
	// 8 entries — anything else falls back to the default (never rejected).
	PadBuckets []int
	// MaxPad is the per-bucket pad cap. 0 = default (MaxPad = 64); clamped
	// to 0..=64.
	MaxPad int
	// BigFramePadMax is the pad draw bound for frames exceeding every bucket.
	// 0 = default (4096); clamped to 0..=4096.
	BigFramePadMax int
}

// resolve applies the zero-value defaults and clamps both fields into the
// wire-safe ranges. Mirrors reliable.rs ChannelParams engine clamps.
func (p RtcChannelParams) resolve() (chunk, window int) {
	chunk = p.Chunk
	if chunk == 0 {
		chunk = Chunk
	}
	if chunk < MinChunk {
		chunk = MinChunk
	}
	if chunk > MaxChunk {
		chunk = MaxChunk
	}
	window = p.Window
	if window == 0 {
		window = Window
	}
	if window < MinWindow {
		window = MinWindow
	}
	if window > MaxWindow {
		window = MaxWindow
	}
	return chunk, window
}

// Survival-axis defaults and clamp ranges (D1-D3 + pad axis). The keepalive
// default lives with the mask engine (rtc.go keepaliveEvery); all knobs are
// normalized here so one params struct carries every RTC axis.
const (
	rtoMinClampLo, rtoMinClampMs       = 50.0, 500.0
	rtoMaxClampLo, rtoMaxClampMs       = 1000.0, 10000.0
	bufferCapClampLo, bufferCapClampHi = 128, 2048
	keepaliveClampLo, keepaliveClampHi = 2 * time.Second, 15 * time.Second
	bigFramePadMaxClampHi              = 4096
	defaultBigFramePadMax              = 4096
	// Pad-bucket bounds live in crypto.go (padBucketMin/padBucketMax/
	// maxPadBucketCount) — one vocabulary for the ws and rtc pad axes.
)

func clampIntRange(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampFloatRange(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampDurationRange(v, lo, hi time.Duration) time.Duration {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// validPadBuckets enforces the rtc pad-axis validation (the []int twin of
// crypto.go's fail-closing validatePadBuckets): strictly ascending, every
// value within 256..=65536, at most 8 entries (crypto.go's maxPadBucketCount).
func validPadBuckets(buckets []int) bool {
	if len(buckets) == 0 || len(buckets) > maxPadBucketCount {
		return false
	}
	prev := 0
	for _, v := range buckets {
		if v < padBucketMin || v > padBucketMax || v <= prev {
			return false
		}
		prev = v
	}
	return true
}

// normalize returns a clamped/validated copy of the params: zero fields
// become the current defaults, out-of-range values land on the nearest
// wire-safe bound, invalid pad bucket sets fall back to the default set
// (never rejected, never aliased). Constructors run this before use.
func (p RtcChannelParams) normalize() RtcChannelParams {
	n := p
	n.Chunk, n.Window = p.resolve()
	n.RtoMinMs = clampFloatRange(zeroDefaultFloat(p.RtoMinMs, rtoMinMs), rtoMinClampLo, rtoMinClampMs)
	n.RtoMaxMs = clampFloatRange(zeroDefaultFloat(p.RtoMaxMs, rtoMaxMs), rtoMaxClampLo, rtoMaxClampMs)
	n.BufferCap = clampIntRange(zeroDefaultInt(p.BufferCap, bufferCap), bufferCapClampLo, bufferCapClampHi)
	if p.KeepaliveEvery == 0 {
		p.KeepaliveEvery = keepaliveEvery
	}
	n.KeepaliveEvery = clampDurationRange(p.KeepaliveEvery, keepaliveClampLo, keepaliveClampHi)
	if !validPadBuckets(p.PadBuckets) {
		n.PadBuckets = append([]int(nil), defaultPadBuckets[:]...)
	} else {
		n.PadBuckets = append([]int(nil), p.PadBuckets...)
	}
	n.MaxPad = clampIntRange(zeroDefaultInt(p.MaxPad, MaxPad), 0, MaxPad)
	n.BigFramePadMax = clampIntRange(zeroDefaultInt(p.BigFramePadMax, defaultBigFramePadMax), 0, bigFramePadMaxClampHi)
	return n
}

func zeroDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func zeroDefaultFloat(v, def float64) float64 {
	if v == 0 {
		return def
	}
	return v
}

// FecGroup is the historical group size, retained for compatibility and
// regression diagnostics only. Legacy FEC is unsupported.
const FecGroup = 32 / 8

// RTO bounds (retransmission timeout, milliseconds) ported from reliable.rs.
const (
	rtoMinMs = 250.0
	rtoMaxMs = 3000.0
)

// ParitySeq is the body-kind marker for parity packets (plaintext prefix;
// stream seq 0 is reserved for parity).
const ParitySeq uint32 = 0

// Per-direction out-of-order buffer cap.
const bufferCap = 512

// Counter-space separation between data / parity / ack / keepalive packets so
// a single ChaCha cipher can serve all four without nonce reuse.
const (
	dataCounterBase      uint64 = 1 << 40
	parityCounterBase    uint64 = 2 << 40
	ackCounterBase       uint64 = 3 << 40
	keepaliveCounterBase uint64 = 4 << 40
)

// MaskSeal seals one body at a counter; provided by the mask layer (rtc.go).
type MaskSeal func(counter uint64, body []byte) []byte

// reliablePacket is one sealed packet ready for the wire, tagged with the
// counter space it belongs to (data / parity / ack / keepalive).
type reliablePacket struct {
	Counter uint64
	Body    []byte
}

type inFlight struct {
	seq         uint32
	counter     uint64
	sealed      []byte
	firstSent   time.Time
	retransmits int
}

// OutChannel is the sending side: chunking, windowing and RTO retransmission.
type OutChannel struct {
	seal     MaskSeal
	window   int
	rtoMinMs float64 // retransmission floor (D1 axis)
	rtoMaxMs float64 // retransmission ceiling (D1 axis)
	nextSeq  uint32
	unacked  []inFlight
	srtt     float64
	hasSrtt  bool
	rto      float64 // milliseconds
}

func newOutChannel(seal MaskSeal) *OutChannel {
	return newOutChannelWindow(seal, Window)
}

// newOutChannelWindow builds the sender with an explicit backpressure window
// (the per-direction RtcChannelParams.Window; caller resolves/clamps) and the
// default RTO bounds.
func newOutChannelWindow(seal MaskSeal, window int) *OutChannel {
	return newOutChannelAxis(seal, window, rtoMinMs, rtoMaxMs)
}

// newOutChannelAxis builds the sender with explicit window + RTO bounds (the
// D1 axis; caller resolves/clamps via RtcChannelParams.normalize).
func newOutChannelAxis(seal MaskSeal, window int, rtoMinMs, rtoMaxMs float64) *OutChannel {
	if window < 1 {
		window = Window
	}
	return &OutChannel{
		seal:     seal,
		window:   window,
		rtoMinMs: rtoMinMs,
		rtoMaxMs: rtoMaxMs,
		nextSeq:  1,
		rto:      500.0,
	}
}

// trySend queues one stream chunk and returns the packets to put on the wire
// — one data packet, without unsafe legacy parity — or an
// empty slice when the window is full (the caller retries after acks arrive).
func (o *OutChannel) trySend(chunk []byte, now time.Time) []reliablePacket {
	if len(o.unacked) >= o.window {
		return nil
	}
	seq := o.nextSeq
	body := make([]byte, 4, 4+len(chunk))
	binaryBigEndianPutUint32(body, seq)
	body = append(body, chunk...)
	counter := dataCounterBase + uint64(seq)
	sealed := o.seal(counter, body)
	o.unacked = append(o.unacked, inFlight{
		seq:       seq,
		counter:   counter,
		sealed:    append([]byte{}, sealed...),
		firstSent: now,
	})
	o.nextSeq++

	out := make([]reliablePacket, 0, 2)
	out = append(out, reliablePacket{Counter: counter, Body: sealed})

	// Legacy XOR parity carries no original shard lengths. A peer can
	// reconstruct a short shard with a zero tail and corrupt its frame
	// stream. Do not send it; authenticated originals remain retransmittable.
	return out
}

// onAck processes an ACK: cumulative ackedUpto plus a 32-bit SACK bitmap for
// ackedUpto+1 ..= ackedUpto+32. Scans the whole window (SACK must see past
// holes), slides it, and adapts RTO on first-transmission samples.
func (o *OutChannel) onAck(ackedUpto uint32, bitmap uint32, now time.Time) {
	i := 0
	for i < len(o.unacked) {
		f := &o.unacked[i]
		seq := f.seq
		sacked := seq <= ackedUpto+32 && seq > ackedUpto &&
			bitmap&(1<<(seq-ackedUpto-1)) != 0
		if seq <= ackedUpto || sacked {
			if f.retransmits == 0 {
				elapsed := now.Sub(f.firstSent)
				if elapsed < 0 {
					elapsed = 0
				}
				sample := elapsed.Seconds() * 1000.0
				if !o.hasSrtt {
					o.srtt = sample
					o.hasSrtt = true
				} else {
					o.srtt = o.srtt*0.875 + sample*0.125
				}
				rto := o.srtt*2.0 + 40.0
				if rto < o.rtoMinMs {
					rto = o.rtoMinMs
				}
				if rto > o.rtoMaxMs {
					rto = o.rtoMaxMs
				}
				o.rto = rto
			}
			o.unacked = append(o.unacked[:i], o.unacked[i+1:]...)
		} else {
			i++
		}
	}
}

// pollRetransmit retransmits aged unacked packets (the original sealed bytes)
// with exponential backoff: only packets whose age >= the current RTO are
// emitted, and each emission round grows the RTO.
func (o *OutChannel) pollRetransmit(now time.Time) []reliablePacket {
	var out []reliablePacket
	rto := o.rto
	for i := range o.unacked {
		f := &o.unacked[i]
		elapsed := now.Sub(f.firstSent)
		if elapsed < 0 {
			elapsed = 0
		}
		if elapsed.Seconds()*1000.0 >= rto {
			f.retransmits++
			f.firstSent = now
			out = append(out, reliablePacket{Counter: f.counter, Body: append([]byte{}, f.sealed...)})
		}
	}
	if len(out) > 0 {
		rto *= 1.5
		if rto > o.rtoMaxMs {
			rto = o.rtoMaxMs
		}
		o.rto = rto
	}
	return out
}

func (o *OutChannel) windowFree() bool {
	return len(o.unacked) < o.window
}

// InChannel is the receiving side: in-order delivery, out-of-order buffering,
// ACK bookkeeping. Only original data packets can advance the stream.
type InChannel struct {
	expected  uint32
	recv      map[uint32][]byte
	ready     [][]byte
	ackDirty  bool
	bufferCap int // out-of-order cache cap (D2 axis)
}

func newInChannel() *InChannel {
	return newInChannelCap(bufferCap)
}

// newInChannelCap builds the receiver with an explicit out-of-order cache cap
// (the per-direction RtcChannelParams.BufferCap; caller resolves/clamps).
func newInChannelCap(capacity int) *InChannel {
	if capacity < 1 {
		capacity = bufferCap
	}
	return &InChannel{
		expected:  1,
		recv:      make(map[uint32][]byte),
		bufferCap: capacity,
	}
}

// onDataBody feeds a data body [u32 seq][chunk]. It returns true when new
// in-order bytes became available (the caller then drains takeReady).
func (in *InChannel) onDataBody(body []byte) bool {
	if len(body) < 4 {
		return false
	}
	seq := uint32FromBE(body[:4])
	chunk := body[4:]
	if seq < in.expected {
		return false // duplicate/old
	}
	in.recv[seq] = append([]byte{}, chunk...)
	in.ackDirty = true
	return in.deliverReady()
}

// deliverReady moves contiguous bodies from recv into ready.
func (in *InChannel) deliverReady() bool {
	moved := false
	for {
		chunk, ok := in.recv[in.expected]
		if !ok {
			break
		}
		in.ready = append(in.ready, chunk)
		delete(in.recv, in.expected)
		in.expected++
		moved = true
	}
	if len(in.recv) > in.bufferCap {
		// hopeless desync: drop out-of-order cache (retransmits refill it)
		for k := range in.recv {
			if k >= in.expected {
				delete(in.recv, k)
			}
		}
	}
	return moved
}

// takeReady drains in-order chunk payloads.
func (in *InChannel) takeReady() [][]byte {
	out := in.ready
	in.ready = nil
	return out
}

// takeAck returns the current pending ACK (cumulative + SACK bitmap) and
// clears the dirty flag.
func (in *InChannel) takeAck() (upto uint32, bitmap uint32, ok bool) {
	if !in.ackDirty {
		return 0, 0, false
	}
	in.ackDirty = false
	upto = in.expected - 1
	for i := uint32(0); i < 32; i++ {
		if _, present := in.recv[upto+1+i]; present {
			bitmap |= 1 << i
		}
	}
	return upto, bitmap, true
}

// expectedSeq is the next expected stream seq (observability/tests).
func (in *InChannel) expectedSeq() uint32 {
	return in.expected
}

func binaryBigEndianPutUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func uint32FromBE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
