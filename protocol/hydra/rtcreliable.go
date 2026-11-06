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
const Chunk = 1150

// Window is the max unacked data packets in flight (backpressure window).
const Window = 128

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
	seal    MaskSeal
	nextSeq uint32
	unacked []inFlight
	srtt    float64
	hasSrtt bool
	rto     float64 // milliseconds
}

func newOutChannel(seal MaskSeal) *OutChannel {
	return &OutChannel{
		seal:    seal,
		nextSeq: 1,
		rto:     500.0,
	}
}

// trySend queues one stream chunk and returns the packets to put on the wire
// — one data packet, without unsafe legacy parity — or an
// empty slice when the window is full (the caller retries after acks arrive).
func (o *OutChannel) trySend(chunk []byte, now time.Time) []reliablePacket {
	if len(o.unacked) >= Window {
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
				if rto < rtoMinMs {
					rto = rtoMinMs
				}
				if rto > rtoMaxMs {
					rto = rtoMaxMs
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
		if rto > rtoMaxMs {
			rto = rtoMaxMs
		}
		o.rto = rto
	}
	return out
}

func (o *OutChannel) windowFree() bool {
	return len(o.unacked) < Window
}

// InChannel is the receiving side: in-order delivery, out-of-order buffering,
// ACK bookkeeping. Only original data packets can advance the stream.
type InChannel struct {
	expected uint32
	recv     map[uint32][]byte
	ready    [][]byte
	ackDirty bool
}

func newInChannel() *InChannel {
	return &InChannel{
		expected: 1,
		recv:     make(map[uint32][]byte),
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
	if len(in.recv) > bufferCap {
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
