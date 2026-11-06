package hydra

// Session negotiation (frame types 8 NEGOTIATE / 9 ACCEPT / 10 REJECT).
//
// Go port of the Rust engine in hydra/src/negotiate.rs: the client offers
// parameters in one plaintext AEAD frame after CONFIRM and before any OPEN;
// the server either ACCEPTs the applied subset or REJECTs with a reason.
// Legacy servers ignore unknown frame types (dispatch falls through), so an
// offer left unanswered within negotiateReplyTimeout falls back to legacy
// mode; a REJECT or malformed reply is a sticky failure for the connection.
// Either way the tunnel keeps working: negotiation failure never fails it.
//
// Wire (inside an AEAD frame, connection-scoped, no session id):
//   NEGOTIATE client->server: [8][u8 ver=1][u16 tlv_count][tlv*], total <= 512
//   ACCEPT    server->client: [9][u16 tlv_count][tlv*] — only APPLIED params
//   REJECT    server->client: [10][u8 reason_len][reason<=255]
//   tlv = [u16 tag][u16 len][bytes]; tag 1 = MAX_FRAME, u32 BE, 1024..=65536

import (
	"encoding/binary"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/log"
)

// Wire constants (negotiate.rs).
const (
	negotiateType    = 8
	acceptType       = 9
	rejectType       = 10
	negotiateVersion = 1
	// tagMaxFrame is the only whitelisted tag: u32 BE, 1024..=65536.
	tagMaxFrame = 1
	// negotiateMax caps the total NEGOTIATE/ACCEPT plaintext size.
	negotiateMax = 512
	// maxFrameMin/maxFrameMax bound MAX_FRAME (total frame incl. the 17 B
	// overhead).
	maxFrameMin = 1024
	maxFrameMax = 65536
	// frameOverhead is the per-DATA-frame cost: 1 type byte + 16-byte id.
	frameOverhead = 17
	// legacyDataChunk is the DATA payload chunk size every existing sender
	// already uses (Rust LEGACY_DATA_CHUNK).
	legacyDataChunk = 16384
)

// negotiateReplyTimeout bounds the ACCEPT/REJECT wait after the offer
// (Rust: 5 s). Package var seam: tests shorten it — the deadline is computed
// from time.Now, no Instant plumbing.
var negotiateReplyTimeout = 5 * time.Second

// negotiateError mirrors the Rust NegotiateError variants; rejectReason maps
// each to the deterministic wire reason string (golden-vector material).
type negotiateError struct {
	kind string // "short","bad-type","bad-version","bad-count","bad-len","duplicate-tag","trailing","unknown-tag","oversize","max-frame-range","bad-utf8"
	b    byte
	tag  uint16
	val  uint32
}

func (e *negotiateError) Error() string {
	switch e.kind {
	case "bad-type":
		return "hydra negotiate: bad type byte"
	case "bad-version":
		return "hydra negotiate: bad version"
	case "bad-len":
		return "hydra negotiate: bad tag length"
	case "duplicate-tag":
		return "hydra negotiate: duplicate tag"
	case "unknown-tag":
		return "hydra negotiate: unknown tag"
	case "max-frame-range":
		return "hydra negotiate: max_frame out of range"
	default:
		return "hydra negotiate: malformed"
	}
}

// rejectReason mirrors Rust reject_reason: the deterministic wire reason for
// a parse error. These strings are golden-vector material.
func rejectReason(err error) string {
	e, ok := err.(*negotiateError)
	if !ok {
		return "malformed"
	}
	switch e.kind {
	case "bad-version":
		return "unsupported ver"
	case "unknown-tag":
		return "unknown tag " + strconv.FormatUint(uint64(e.tag), 10)
	case "oversize":
		return "oversize frame"
	case "max-frame-range":
		return "max_frame out of range"
	case "duplicate-tag":
		return "duplicate tag"
	default:
		return "malformed"
	}
}

// negotiateParams mirrors Rust NegotiateParams. maxFrame==0 means "not
// offered/applied" (0 can never be a valid value: range is 1024..=65536).
type negotiateParams struct {
	maxFrame uint32
}

// buildNegotiate serializes [8][ver=1][count=1][tag=1][len=4][mf]. It
// validates the range and returns nil for values outside 1024..=65536 (the
// caller then skips negotiation instead of offering an invalid frame).
func buildNegotiate(maxFrame uint32) []byte {
	if maxFrame < maxFrameMin || maxFrame > maxFrameMax {
		return nil
	}
	out := make([]byte, 0, 12)
	out = append(out, negotiateType, negotiateVersion, 0, 1)
	out = binary.BigEndian.AppendUint16(out, tagMaxFrame)
	out = binary.BigEndian.AppendUint16(out, 4)
	out = binary.BigEndian.AppendUint32(out, maxFrame)
	return out
}

// parseNegotiate mirrors Rust parse_negotiate (the whole plaintext).
func parseNegotiate(frame []byte) (negotiateParams, error) {
	if len(frame) > negotiateMax {
		return negotiateParams{}, &negotiateError{kind: "oversize"}
	}
	if len(frame) < 4 {
		return negotiateParams{}, &negotiateError{kind: "short"}
	}
	if frame[0] != negotiateType {
		return negotiateParams{}, &negotiateError{kind: "bad-type", b: frame[0]}
	}
	if frame[1] != negotiateVersion {
		return negotiateParams{}, &negotiateError{kind: "bad-version", b: frame[1]}
	}
	return walkTLVs(frame, int(binary.BigEndian.Uint16(frame[2:4])), 4)
}

// buildAccept serializes [9][count][tlv*] with only the applied params.
func buildAccept(applied negotiateParams) []byte {
	out := make([]byte, 0, 11)
	out = append(out, acceptType, 0, 1)
	out = binary.BigEndian.AppendUint16(out, tagMaxFrame)
	out = binary.BigEndian.AppendUint16(out, 4)
	out = binary.BigEndian.AppendUint32(out, applied.maxFrame)
	return out
}

// parseAccept mirrors Rust parse_accept (the whole plaintext).
func parseAccept(b []byte) (negotiateParams, error) {
	if len(b) > negotiateMax {
		return negotiateParams{}, &negotiateError{kind: "oversize"}
	}
	if len(b) < 3 {
		return negotiateParams{}, &negotiateError{kind: "short"}
	}
	if b[0] != acceptType {
		return negotiateParams{}, &negotiateError{kind: "bad-type", b: b[0]}
	}
	return walkTLVs(b, int(binary.BigEndian.Uint16(b[1:3])), 3)
}

// buildReject serializes [10][u8 reason_len][reason], truncated to 255 bytes
// without cutting a UTF-8 character in half (Rust char-boundary semantics).
func buildReject(reason string) []byte {
	end := len(reason)
	if end > 255 {
		end = 255
	}
	for end > 0 && end < len(reason) && !utf8.RuneStart(reason[end]) {
		end--
	}
	out := make([]byte, 0, 2+end)
	out = append(out, rejectType, byte(end))
	out = append(out, reason[:end]...)
	return out
}

// parseReject mirrors Rust parse_reject; returns the reason string.
func parseReject(b []byte) (string, error) {
	if len(b) < 2 {
		return "", &negotiateError{kind: "short"}
	}
	if b[0] != rejectType {
		return "", &negotiateError{kind: "bad-type", b: b[0]}
	}
	n := int(b[1])
	if len(b) != 2+n {
		return "", &negotiateError{kind: "trailing"}
	}
	if !utf8.Valid(b[2:]) {
		return "", &negotiateError{kind: "bad-utf8"}
	}
	return string(b[2:]), nil
}

// walkTLVs is the strict TLV walker: exactly count TLVs from i, no
// truncation, no trailing bytes, whitelist + value validation, duplicates
// rejected (negotiate.rs walk_tlvs).
func walkTLVs(b []byte, count int, i int) (negotiateParams, error) {
	var p negotiateParams
	for k := 0; k < count; k++ {
		if len(b) < i+4 {
			return p, &negotiateError{kind: "bad-count"}
		}
		tag := binary.BigEndian.Uint16(b[i:])
		l := int(binary.BigEndian.Uint16(b[i+2:]))
		i += 4
		if len(b) < i+l {
			return p, &negotiateError{kind: "bad-count"}
		}
		val := b[i : i+l]
		i += l
		switch tag {
		case tagMaxFrame:
			if p.maxFrame != 0 {
				return p, &negotiateError{kind: "duplicate-tag", tag: tag}
			}
			if l != 4 {
				return p, &negotiateError{kind: "bad-len", tag: tag}
			}
			mf := binary.BigEndian.Uint32(val)
			if mf < maxFrameMin || mf > maxFrameMax {
				return p, &negotiateError{kind: "max-frame-range", val: mf}
			}
			p.maxFrame = mf
		default:
			return p, &negotiateError{kind: "unknown-tag", tag: tag}
		}
	}
	if i != len(b) {
		return p, &negotiateError{kind: "trailing"}
	}
	return p, nil
}

// dataChunkCap mirrors Rust negotiate::data_chunk_cap: the DATA payload chunk
// cap for a connection negotiated to maxFrame —
// min(legacyDataChunk, maxFrame-frameOverhead); no negotiation (0) means the
// legacy 16384. A LARGER negotiated max_frame never raises the legacy chunk
// size (clamp only).
func dataChunkCap(maxFrame uint32) int {
	if maxFrame == 0 {
		return legacyDataChunk
	}
	c := int(maxFrame) - frameOverhead
	if c < 0 {
		c = 0
	}
	if c > legacyDataChunk {
		c = legacyDataChunk
	}
	return c
}

// ---------------------------------------------------------------------------
// Client state machine (negotiate.rs ClientNegotiation).
// ---------------------------------------------------------------------------

type clientPhase uint8

const (
	clientPhaseLegacy clientPhase = iota
	clientPhaseOffered
	clientPhaseAccepted
	clientPhaseFailed
)

type clientEventKind uint8

const (
	clientEventNone clientEventKind = iota
	clientEventNegotiated
	clientEventRejected
)

// clientEvent mirrors the Rust ClientEvent members the tunnel consumes
// (Send is handled by the caller before the wait loop starts).
type clientEvent struct {
	kind   clientEventKind
	params negotiateParams
	reason string
}

// clientNegotiation mirrors Rust ClientNegotiation: one outstanding offer per
// connection, duplicate identical ACCEPTs idempotent, stale/conflicting
// replies ignored, a well-formed-looking 9/10 that fails to parse is sticky
// failure ("misbehaving peer"), an offer past its deadline falls back to
// legacy.
type clientNegotiation struct {
	phase    clientPhase
	accepted negotiateParams
}

// offer starts negotiating; only legal from the legacy phase.
func (c *clientNegotiation) offer() bool {
	if c.phase != clientPhaseLegacy {
		return false
	}
	c.phase = clientPhaseOffered
	return true
}

// expire is ClientNegotiation::poll at/after the deadline: an unanswered
// offer falls back to legacy (the peer ignored the unknown type or the reply
// was lost) — keep working.
func (c *clientNegotiation) expire() {
	if c.phase == clientPhaseOffered {
		c.phase = clientPhaseLegacy
	}
}

// onFrame feeds one decrypted frame; types 9/10 route here, anything else is
// ignored (session traffic and unknown types are not negotiation).
func (c *clientNegotiation) onFrame(plain []byte) clientEvent {
	if len(plain) == 0 {
		return clientEvent{}
	}
	switch plain[0] {
	case acceptType:
		applied, err := parseAccept(plain)
		if err != nil {
			return c.failMalformed()
		}
		switch c.phase {
		case clientPhaseOffered:
			c.phase = clientPhaseAccepted
			c.accepted = applied
			return clientEvent{kind: clientEventNegotiated, params: applied}
		case clientPhaseAccepted:
			if c.accepted == applied {
				// duplicate ACCEPT: idempotent, no state change
				return clientEvent{kind: clientEventNegotiated, params: applied}
			}
			// stale duplicate or a CONFLICTING accept: first offer wins
			return clientEvent{}
		default:
			return clientEvent{}
		}
	case rejectType:
		reason, err := parseReject(plain)
		if err != nil {
			return c.failMalformed()
		}
		if c.phase == clientPhaseOffered {
			c.phase = clientPhaseFailed
			return clientEvent{kind: clientEventRejected, reason: reason}
		}
		// stale REJECT for an already-settled negotiation
		return clientEvent{}
	default:
		return clientEvent{}
	}
}

// failMalformed: a 9/10 frame that looks well-formed but fails to parse is a
// misbehaving peer — sticky failure instead of guessing.
func (c *clientNegotiation) failMalformed() clientEvent {
	if c.phase == clientPhaseOffered {
		c.phase = clientPhaseFailed
		return clientEvent{kind: clientEventRejected, reason: "malformed"}
	}
	return clientEvent{}
}

// ---------------------------------------------------------------------------
// Tunnel integration.
// ---------------------------------------------------------------------------

// negotiate sends the offer right after CONFIRM and before any OPEN, then
// waits for ACCEPT/REJECT within negotiateReplyTimeout. Every outcome keeps
// the tunnel alive: ACCEPT applies max_frame, REJECT/malformed is sticky
// failure, timeout is the legacy fallback for servers that ignore unknown
// frame types.
func (t *Tunnel) negotiate(offer []byte, logger log.ContextLogger) {
	if !t.neg.offer() {
		return // only one outstanding offer per connection
	}
	if !t.send(offer) {
		return // tunnel died before the offer hit the wire
	}
	timer := time.NewTimer(negotiateReplyTimeout)
	defer timer.Stop()
	for {
		select {
		case plain := <-t.negCh:
			ev := t.neg.onFrame(plain)
			switch ev.kind {
			case clientEventNegotiated:
				if ev.params.maxFrame != 0 {
					t.maxFrame = ev.params.maxFrame
					t.negotiationResult = "accepted max_frame=" + strconv.FormatUint(uint64(ev.params.maxFrame), 10)
				} else {
					t.negotiationResult = "accepted (no params applied)"
				}
				t.logNegotiation(logger)
				return
			case clientEventRejected:
				// sticky failure: the connection keeps working in legacy mode
				t.negotiationResult = "rejected: " + ev.reason
				t.logNegotiation(logger)
				return
			}
			// clientEventNone: unexpected duplicate while waiting — keep going
		case <-timer.C:
			t.neg.expire()
			t.negotiationResult = "timeout: legacy fallback"
			t.logNegotiation(logger)
			return
		case <-t.done:
			return
		}
	}
}

// deliverNegotiation moves one decrypted 9/10 frame from the reader to the
// negotiation waiter. Never blocks: a settled negotiation simply drops late
// strays (the same frames Rust's client engine returns None for).
func (t *Tunnel) deliverNegotiation(plain []byte) {
	select {
	case t.negCh <- plain:
	default:
	}
}

// NegotiatedMaxFrame reports the negotiated maximum total frame size, 0 when
// the connection stayed legacy (disabled, timeout, reject or malformed).
func (t *Tunnel) NegotiatedMaxFrame() uint32 { return t.maxFrame }

// NegotiationStatus reports how the connection negotiation settled.
func (t *Tunnel) NegotiationStatus() string { return t.negotiationResult }

// chunkLimit is the DATA payload split size for session writes: 0 keeps the
// legacy unchunked write path byte-identical to pre-negotiation behavior; a
// negotiated max_frame yields dataChunkCap(maxFrame) =
// min(16384, maxFrame-17).
func (t *Tunnel) chunkLimit() int {
	if t.maxFrame == 0 {
		return 0
	}
	return dataChunkCap(t.maxFrame)
}

func (t *Tunnel) logNegotiation(logger log.ContextLogger) {
	if logger != nil {
		logger.Info("hydra negotiate: ", t.negotiationResult)
	}
}
