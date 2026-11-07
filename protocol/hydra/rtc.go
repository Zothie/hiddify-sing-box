package hydra

// RTC mask — the Go port of hydra's WebRTC-shaped UDP transport engine
// (vpns/hydra src/rtc.rs).
//
// Architecture (mirrors the Rust reference):
//   - Handshake: STUN Binding exchange (RFC 5389 shapes, MESSAGE-INTEGRITY +
//     FINGERPRINT under a key derived from the configured server static
//     pubkey and a fresh salt — pre-auth, REALITY-style: junk never allocates
//     state). The hydra hello [salt16][sealed(MAGIC+eph)] rides an opaque
//     optional attribute; the server reply rides the response. From then on
//     the data plane is byte-identical to ws mode: same frame cipher
//     (kdfAuth over the ephemeral transcript), same counters, same
//     frameStream decoding.
//   - Data plane: hydra frames are chunked by the reliable layer and sealed
//     with a dedicated RTC cipher; each packet wears an RTP header (V=2,
//     PT 111 opus / PT 100 fec) with a 48 kHz media clock; parity wears
//     ULPFEC-style PT 100.
//   - Control: ACKs as RTCP Receiver Reports, keepalives as RTCP Sender
//     Reports plus ICE consent-freshness STUN checks — the packet mix a real
//     WebRTC call produces.
//
// This wave ships the engine only; wiring into the sing-box outbound is a
// later step.

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Engine timing constants ported from rtc.rs.
const (
	// wireBudget is the hard datagram budget (stays under the 1280-byte IPv6
	// minimum MTU).
	wireBudget = 1220
	// handshakeTimeout bounds the handshake.
	rtcHandshakeTimeout = 12 * time.Second
	// idleTimeout declares the flow dead with no verified inbound traffic.
	idleTimeout = 30 * time.Second
	// keepaliveEvery is the DEFAULT keepalive cadence (RTCP SR + ICE consent
	// refresh); candidates override it through RtcChannelParams.KeepaliveEvery
	// (the packet shape never changes, only this timer).
	keepaliveEvery = 5 * time.Second
	// helloRetry is the client hello retransmit cadence while handshaking.
	helloRetry = time.Second
)

// stunKey derives the STUN integrity key: computable by both sides from the
// CONFIGURED server static pubkey + the fresh salt; nothing else can produce
// it.
func stunKey(serverStaticPub, salt []byte) [32]byte {
	material := make([]byte, 0, len(serverStaticPub)+len(salt))
	material = append(material, serverStaticPub...)
	material = append(material, salt...)
	var key [32]byte
	copy(key[:], deriveKey("hydra-rtc-stun-v1", material))
	return key
}

// rtcDataKey derives the dedicated RTC datagram cipher key (separate domain
// from the frame cipher).
func rtcDataKey(sharedEph, sharedStatic, salt, transcript []byte) [32]byte {
	material := make([]byte, 0, len(sharedEph)+len(sharedStatic)+len(salt)+len(transcript))
	material = append(material, sharedEph...)
	material = append(material, sharedStatic...)
	material = append(material, salt...)
	material = append(material, transcript...)
	var key [32]byte
	copy(key[:], deriveKey("hydra-rtc-data-v1", material))
	return key
}

func mustAEAD(key [32]byte) cipher.AEAD {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		// Unreachable for a 32-byte key (chacha20poly1305.New only fails on
		// key length); mirrors the Rust expect("key len").
		panic("hydra: chacha20poly1305 init failed: " + err.Error())
	}
	return aead
}

// maskRand abstracts every randomness the mask engine consumes: raw bytes
// (salt, txn, ICE-CONTROLLING, AEAD nonce prefix, padding), inclusive bucket
// draws, and the local ephemeral keypair (public key + DH resolution against
// the peer's ephemeral public key). The default source is crypto/rand +
// X25519; tests inject deterministic sources to reproduce golden vectors.
type maskRand interface {
	fill(p []byte)
	intn(n int) int // uniform in [0, n] inclusive
	ephKeyPair() (pub [32]byte, dh func(peerPub [32]byte) []byte)
}

type osMaskRand struct{}

func (osMaskRand) fill(p []byte) {
	// crypto/rand never fails on Linux short reads; a failure leaves zeros,
	// matching the tolerance in crypto.go's sealCtr.
	_, _ = rand.Read(p)
}

func (osMaskRand) intn(n int) int { return randRangeInclusive(n) }

func (osMaskRand) ephKeyPair() ([32]byte, func(peerPub [32]byte) []byte) {
	priv := make([]byte, 32)
	_, _ = rand.Read(priv)
	pub, err := x25519Pub(priv)
	if err != nil {
		panic("hydra: x25519 pubkey: " + err.Error())
	}
	var pub32 [32]byte
	copy(pub32[:], pub)
	return pub32, func(peerPub [32]byte) []byte {
		shared, err := x25519(priv, peerPub[:])
		if err != nil {
			panic("hydra: x25519 dh: " + err.Error())
		}
		return shared
	}
}

var defaultMaskRand maskRand = osMaskRand{}

// sealMaskWith seals one mask-layer body: nonce12[4 rand + counter BE] || ct,
// AAD = MAGIC + counter (the same construction as proto frames, so the
// counter is embedded and recoverable before decryption).
func sealMaskWith(aead cipher.AEAD, counter uint64, body []byte, rs maskRand) []byte {
	nonce := make([]byte, NonceSize)
	rs.fill(nonce[:4])
	binary.BigEndian.PutUint64(nonce[4:], counter)
	ct := aead.Seal(nil, nonce, body, aadFor(counter))
	out := make([]byte, 0, NonceSize+len(ct))
	out = append(out, nonce...)
	return append(out, ct...)
}

// openMask opens one mask-layer body and recovers the counter from the
// embedded nonce.
func openMask(aead cipher.AEAD, sealed []byte) (uint64, []byte, bool) {
	if len(sealed) < NonceSize+16 {
		return 0, nil, false
	}
	nonce := sealed[:NonceSize]
	counter := binary.BigEndian.Uint64(nonce[4:])
	plain, err := aead.Open(nil, nonce, sealed[NonceSize:], aadFor(counter))
	if err != nil {
		return 0, nil, false
	}
	return counter, plain, true
}

// rtcPadConfig carries the pad-axis knobs for the mask engine (padTargetWith)
// — the RTC-local twin of crypto.go's ws-path padConfig. Same default shape
// (proto.rs bucket set, MaxPad = 64, big-frame bound 4096) but LITERAL zero
// semantics: maxPad/bigPad 0 means zero padding (deterministic goldens), not
// the ws path's 0-means-default; normalize() decides which value lands here.
// Buckets shape the frame-length histogram an observer sees; maxPad caps the
// draw inside a bucket; bigPad bounds the draw for frames exceeding every
// bucket. padLen travels in-frame, so ANY config stays wire-compatible — the
// receiver is length-agnostic.
type rtcPadConfig struct {
	buckets []int
	maxPad  int
	bigPad  int
}

func defaultPadConfig() rtcPadConfig {
	return rtcPadConfig{
		buckets: append([]int(nil), defaultPadBuckets[:]...),
		maxPad:  MaxPad,
		bigPad:  defaultBigFramePadMax,
	}
}

// padTargetWith mirrors proto.rs pad_target: bucketed padding — round
// (payload+overhead) up to the next bucket, then draw 0..=min(slack, maxPad)
// pad bytes (0..=bigPad for frames exceeding every bucket). An observer learns
// only the size bucket, not the exact payload length.
func padTargetWith(plainLen int, rs maskRand, cfg rtcPadConfig) int {
	need := plainLen + 3 + 16
	for _, b := range cfg.buckets {
		if need <= b {
			slack := b - need
			if slack > cfg.maxPad {
				slack = cfg.maxPad
			}
			return rs.intn(slack)
		}
	}
	return rs.intn(cfg.bigPad)
}

// sealCtrWith is the entropy-driven variant of proto.rs seal_ctr used by the
// mask engine: [u32 ctLen][nonce(4 rand + counter BE)][ct]; the plaintext
// becomes [padLen u16][pad][payload]. Receiving uses crypto.go's openCtr
// (decryption is deterministic, so the shared helper serves both directions).
// Uses the default pad config (pre-handshake hello frames keep the fixed
// proto.rs shape); data frames go through sealCtrPad with the engine's pad
// axis config.
func sealCtrWith(aead cipher.AEAD, counter uint64, plaintext []byte, rs maskRand) []byte {
	return sealCtrPad(aead, counter, plaintext, rs, defaultPadConfig())
}

// sealCtrPad is sealCtrWith with an explicit pad config (the pad axis).
// padLen travels in-frame, so any config is wire-compatible.
func sealCtrPad(aead cipher.AEAD, counter uint64, plaintext []byte, rs maskRand, cfg rtcPadConfig) []byte {
	nonce := make([]byte, NonceSize)
	rs.fill(nonce[:4])
	binary.BigEndian.PutUint64(nonce[4:], counter)

	padLen := padTargetWith(len(plaintext), rs, cfg)
	inner := make([]byte, 2+padLen+len(plaintext))
	binary.BigEndian.PutUint16(inner, uint16(padLen))
	if padLen > 0 {
		rs.fill(inner[2 : 2+padLen])
	}
	copy(inner[2+padLen:], plaintext)

	ct := aead.Seal(nil, nonce, inner, aadFor(counter))
	out := make([]byte, 0, SealHeaderSize+len(ct))
	out = binary.BigEndian.AppendUint32(out, uint32(len(ct)))
	out = append(out, nonce...)
	return append(out, ct...)
}

// RtcPoll is the outgoing poll result handed to the caller.
type RtcPoll struct {
	// Wire holds UDP datagrams to transmit to the peer.
	Wire [][]byte
	// Frames holds decrypted plain protocol frames ready for session dispatch.
	Frames [][]byte
	// Connected reports handshake complete AND the CONFIRM round-trip landed.
	Connected bool
	// Dead reports terminal state (handshake timeout / idle / tamper).
	Dead bool
	// RotateMask reports that the ML-DPI self-gate (dpigate.go) judged the
	// own wire tunnel-like: Dead is set for the same poll so the pump kills
	// the tunnel and the adaptive layer rebuilds it with a fresh mask
	// (Rust tunnel.rs run_rtc_pump: gate raise -> dead.store(true)).
	RotateMask bool
}

type rtcPhase uint8

const (
	phaseHandshake rtcPhase = iota
	phaseData
)

// RtcMask is one endpoint of the masked channel. Client: NewClient. Server:
// NewServer. The engine is synchronous; the caller owns sockets and drives
// Receive/Poll with its own clock.
type RtcMask struct {
	server      bool
	started     time.Time
	lastRx      time.Time
	lastKeepal  time.Time
	lastHello   time.Time
	phase       rtcPhase
	established bool
	// confirmed: client only — CONFIRM frame consumed (server always true).
	confirmed bool

	// mask cosmetics
	ssrc     uint32
	rtpSeq   uint16
	tsOrigin uint32
	peer     netip.AddrPort

	// handshake material
	staticPub  [32]byte
	staticPriv []byte // server only
	salt       [16]byte
	skey       [32]byte
	txn        [12]byte
	clientEpub [32]byte
	// client: cached STUN hello packet for retransmit; server: cached reply.
	cachedPkt []byte
	// client: pending ephemeral DH, consumed once (Rust esc.take()).
	clientDH func(peerPub [32]byte) []byte

	// keys + frame layer
	frameCipher cipher.AEAD
	rtcCipher   cipher.AEAD
	frameOutCtr uint64
	framesIn    *frameStream

	// reliable data plane
	out        *OutChannel
	input      *InChannel
	pendingOut [][]byte
	ackCounter uint64
	kaCounter  uint64
	// chunk/window are THIS endpoint's reliable-layer params after resolve:
	// chunk sizes the frames this endpoint cuts for the wire, window gates
	// this endpoint's own sender. The peer's values are independent; see
	// RtcChannelParams for the both-ends coupling contract.
	chunk  int
	window int
	// rtoMinMs/rtoMaxMs gate this endpoint's retransmission timer (D1 axis),
	// keepaliveEvery is this endpoint's consent/SR cadence (D3 axis, shape
	// unchanged) and padCfg is this endpoint's frame pad shape (pad axis).
	// All are one-sided knobs; coupling notes live on RtcChannelParams.
	rtoMinMs       float64
	rtoMaxMs       float64
	keepaliveEvery time.Duration
	padCfg         rtcPadConfig

	wire [][]byte
	dead bool
	// dpiGate is the optional client ML-DPI self-check (dpigate.go), attached
	// with SetDPIGate before the pump starts. Poll samples it over the final
	// outgoing wire; a raise dead-flags the engine (mask rotation rebuild).
	dpiGate   *ClientSelfGate
	dpiRotate bool

	rs maskRand
}

// NewClient creates the client endpoint; it initiates the masked handshake.
// Default channel params (Chunk 1150 / Window 128) — byte-identical to the
// pre-params engine.
func NewClient(staticPub [32]byte, peer netip.AddrPort, now time.Time) *RtcMask {
	return newClientWithEntropy(staticPub, peer, now, defaultMaskRand)
}

// NewClientWithParams creates the client endpoint with explicit reliable-layer
// channel params (chunk + window). Zero fields keep the current defaults; the
// both-ends coupling contract lives on RtcChannelParams.
func NewClientWithParams(staticPub [32]byte, peer netip.AddrPort, now time.Time, params RtcChannelParams) *RtcMask {
	return newClientWithEntropyParams(staticPub, peer, now, defaultMaskRand, params)
}

// NewServer creates the passive server endpoint; flow state is only completed
// after the STUN integrity check passes (pre-auth gate — junk floods are
// refused before any allocation). Default channel params.
func NewServer(staticPub, staticPriv [32]byte, peer netip.AddrPort, now time.Time) *RtcMask {
	return newServerWithEntropy(staticPub, staticPriv, peer, now, defaultMaskRand)
}

// NewServerWithParams is NewServer with explicit reliable-layer channel
// params (chunk + window) for the server's own direction.
func NewServerWithParams(staticPub, staticPriv [32]byte, peer netip.AddrPort, now time.Time, params RtcChannelParams) *RtcMask {
	return newServerWithEntropyParams(staticPub, staticPriv, peer, now, defaultMaskRand, params)
}

func newClientWithEntropy(staticPub [32]byte, peer netip.AddrPort, now time.Time, rs maskRand) *RtcMask {
	return newClientWithEntropyParams(staticPub, peer, now, rs, RtcChannelParams{})
}

func newClientWithEntropyParams(staticPub [32]byte, peer netip.AddrPort, now time.Time, rs maskRand, params RtcChannelParams) *RtcMask {
	n := params.normalize()
	chunk, window := n.Chunk, n.Window
	salt := make([]byte, 16)
	rs.fill(salt)
	skey := stunKey(staticPub[:], salt)
	epub, dh := rs.ephKeyPair()
	hc, err := kdfHello(staticPub[:], salt)
	if err != nil {
		panic("hydra: kdf_hello: " + err.Error())
	}
	inner := make([]byte, 0, len(Magic)+32)
	inner = append(inner, Magic[:]...)
	inner = append(inner, epub[:]...)
	sealed := sealCtrWith(hc, 0, inner, rs)
	helloAttr := make([]byte, 0, len(salt)+len(sealed))
	helloAttr = append(helloAttr, salt...)
	helloAttr = append(helloAttr, sealed...)
	txn := make([]byte, 12)
	rs.fill(txn)
	iceCtrl := make([]byte, 8)
	rs.fill(iceCtrl)
	pkt := stunBuild(stunBindingRequest, asTxn12(txn), []stunAttr{
		{Typ: AttrUsername, Val: []byte(hex.EncodeToString(salt[:8]) + ":" + hex.EncodeToString(salt[8:]))},
		{Typ: AttrPriority, Val: []byte{0x00, 0x6E, 0x7F, 0xFF}},
		{Typ: AttrIceControlling, Val: iceCtrl},
		{Typ: AttrOpaqueApp, Val: helloAttr},
		{Typ: AttrSoftware, Val: []byte("Google Chrome/141")},
	}, skey[:], true)

	var salt16 [16]byte
	copy(salt16[:], salt)
	m := &RtcMask{
		server:         false,
		started:        now,
		lastRx:         now,
		lastKeepal:     now,
		lastHello:      now,
		phase:          phaseHandshake,
		established:    false,
		confirmed:      false,
		ssrc:           randUint32Max1(),
		rtpSeq:         randUint16(),
		tsOrigin:       randUint32Max1(),
		peer:           peer,
		staticPub:      staticPub,
		salt:           salt16,
		skey:           skey,
		txn:            asTxn12(txn),
		clientEpub:     epub,
		cachedPkt:      append([]byte{}, pkt...),
		clientDH:       dh,
		frameOutCtr:    1, // client data frames start at 1 (as in ws mode)
		out:            placeholderOut(),
		input:          newInChannelCap(n.BufferCap),
		ackCounter:     1,
		kaCounter:      1,
		chunk:          chunk,
		window:         window,
		rtoMinMs:       n.RtoMinMs,
		rtoMaxMs:       n.RtoMaxMs,
		keepaliveEvery: n.KeepaliveEvery,
		padCfg: rtcPadConfig{
			buckets: n.PadBuckets,
			maxPad:  n.MaxPad,
			bigPad:  n.BigFramePadMax,
		},
		wire: [][]byte{append([]byte{}, pkt...)},
		dead: false,
		rs:   rs,
	}
	return m
}

func newServerWithEntropy(staticPub, staticPriv [32]byte, peer netip.AddrPort, now time.Time, rs maskRand) *RtcMask {
	return newServerWithEntropyParams(staticPub, staticPriv, peer, now, rs, RtcChannelParams{})
}

func newServerWithEntropyParams(staticPub, staticPriv [32]byte, peer netip.AddrPort, now time.Time, rs maskRand, params RtcChannelParams) *RtcMask {
	skey := stunKey(staticPub[:], make([]byte, 16))
	n := params.normalize()
	chunk, window := n.Chunk, n.Window
	m := &RtcMask{
		server:         true,
		started:        now,
		lastRx:         now,
		lastKeepal:     now,
		lastHello:      now,
		phase:          phaseHandshake,
		established:    false,
		confirmed:      true,
		ssrc:           randUint32Max1(),
		rtpSeq:         randUint16(),
		tsOrigin:       randUint32Max1(),
		peer:           peer,
		staticPub:      staticPub,
		staticPriv:     append([]byte{}, staticPriv[:]...),
		skey:           skey,
		frameOutCtr:    1, // 1 = CONFIRM, data from 2 (as in ws mode)
		out:            placeholderOut(),
		input:          newInChannelCap(n.BufferCap),
		ackCounter:     1,
		kaCounter:      1,
		chunk:          chunk,
		window:         window,
		rtoMinMs:       n.RtoMinMs,
		rtoMaxMs:       n.RtoMaxMs,
		keepaliveEvery: n.KeepaliveEvery,
		padCfg: rtcPadConfig{
			buckets: n.PadBuckets,
			maxPad:  n.MaxPad,
			bigPad:  n.BigFramePadMax,
		},
		dead: false,
		rs:   rs,
	}
	return m
}

// Peer returns the configured remote address.
func (r *RtcMask) Peer() netip.AddrPort { return r.peer }

// Connected reports handshake complete AND the confirm round-trip landed.
func (r *RtcMask) Connected() bool {
	return r.established && r.confirmed && r.phase == phaseData && !r.dead
}

// IsDead reports terminal state, enforcing the handshake and idle timeouts.
func (r *RtcMask) IsDead(now time.Time) bool {
	if r.dead {
		return true
	}
	if r.phase == phaseHandshake && now.Sub(r.started) > rtcHandshakeTimeout {
		return true
	}
	return now.Sub(r.lastRx) > idleTimeout
}

// SendFrame queues one plain protocol frame for transmission (session layer
// API). Frames are sealed at the per-frame counter, then chunked into the
// reliable layer's pending queue.
func (r *RtcMask) SendFrame(plain []byte) {
	if !r.Connected() || r.dead {
		return
	}
	sealed := sealCtrPad(r.frameCipher, r.frameOutCtr, plain, r.rs, r.padCfg)
	r.frameOutCtr++
	// sealed already carries its [u32 ctLen] prefix — the exact bytes the ws
	// transport would put on the wire; the peer's frameStream decodes them
	// identically.
	for off := 0; off < len(sealed); off += r.chunk {
		end := off + r.chunk
		if end > len(sealed) {
			end = len(sealed)
		}
		r.pendingOut = append(r.pendingOut, append([]byte{}, sealed[off:end]...))
	}
}

func (r *RtcMask) drainPending(now time.Time) {
	for len(r.pendingOut) > 0 {
		if len(r.pendingOut[0]) == 0 {
			r.pendingOut = r.pendingOut[1:]
			continue
		}
		chunk := r.pendingOut[0]
		pkts := r.out.trySend(chunk, now)
		if len(pkts) == 0 {
			break // window full; retried on the next poll
		}
		r.pendingOut = r.pendingOut[1:]
		for _, p := range pkts {
			r.wire = append(r.wire, r.wrap(p.Counter, p.Body, now))
		}
	}
}

// wrap dresses one reliable-layer body for the wire: ACK bodies as RTCP-RR,
// data/parity bodies as RTP with PT 111 / PT 100.
func (r *RtcMask) wrap(counter uint64, body []byte, now time.Time) []byte {
	if counter >= ackCounterBase {
		words := uint16((8 + len(body)) / 4)
		w := words - 1
		if w < 1 {
			w = 1
		}
		return append(rtcpRR(r.ssrc, w), body...)
	}
	pt := RTPPtOpus
	if counter >= parityCounterBase {
		pt = RTPPtFec
	}
	hdr := rtpHeader(r.rtpSeq, r.mediaTs(now), r.ssrc, pt)
	r.rtpSeq++
	return append(hdr[:], body...)
}

// mediaTs advances the 48 kHz media clock from the flow start.
func (r *RtcMask) mediaTs(now time.Time) uint32 {
	elapsed := now.Sub(r.started)
	if elapsed < 0 {
		elapsed = 0
	}
	micros := uint64(elapsed / time.Microsecond)
	return r.tsOrigin + uint32(micros*48/1000)
}

// Receive feeds one inbound UDP datagram.
func (r *RtcMask) Receive(packet []byte, now time.Time) {
	if r.dead {
		return
	}
	if len(packet) < 2 || len(packet) > wireBudget+64 {
		return
	}
	switch {
	case packet[0] <= 3:
		r.receiveStun(packet, now)
	case packet[0]&0xc0 == 0x80:
		r.receiveRTP(packet, now)
	default:
		// DTLS-shaped junk or garbage: drop silently
	}
}

func (r *RtcMask) receiveStun(packet []byte, now time.Time) {
	msg, ok := stunParse(packet)
	if !ok {
		return
	}
	switch {
	// server handshake: Binding request carrying the hello
	case r.server && r.phase == phaseHandshake && msg.MsgType == stunBindingRequest:
		attr := msg.attr(AttrOpaqueApp)
		if attr == nil {
			return
		}
		if len(attr) < 16+5+32 {
			return
		}
		var salt [16]byte
		copy(salt[:], attr[:16])
		key := stunKey(r.staticPub[:], salt[:])
		if !msg.verify(packet, key[:]) {
			return // junk / no capability: no state allocated
		}
		if r.established {
			// duplicate hello (our reply was lost): re-send cached reply
			if salt == r.salt && r.cachedPkt != nil {
				r.wire = append(r.wire, append([]byte{}, r.cachedPkt...))
			}
			return
		}
		helloCipher, err := kdfHello(r.staticPub[:], salt[:])
		if err != nil {
			return
		}
		inner, err := openCtr(helloCipher, 0, attr[16:])
		if err != nil {
			return
		}
		if len(inner) < 5+32 || !bytes.Equal(inner[:5], Magic[:]) {
			return
		}
		var epub [32]byte
		copy(epub[:], inner[5:37])
		r.completeServerHandshake(epub, salt, msg.TxnID, now)

	// server keeps the flow alive: consent-freshness request -> answer
	case r.server && r.phase == phaseData && msg.MsgType == stunBindingRequest:
		if msg.verify(packet, r.skey[:]) {
			r.lastRx = now
			rep := stunBuild(stunBindingResponse, msg.TxnID, []stunAttr{
				{Typ: AttrXorMappedAddress, Val: xorMappedAddress(r.peer.Addr(), r.peer.Port())},
			}, r.skey[:], true)
			r.wire = append(r.wire, rep)
		}

	// client: handshake response / consent response
	case !r.server && msg.MsgType == stunBindingResponse:
		if msg.TxnID != r.txn {
			return
		}
		if !msg.verify(packet, r.skey[:]) {
			return
		}
		r.lastRx = now
		if r.phase == phaseHandshake {
			attr := msg.attr(AttrOpaqueApp)
			if attr == nil {
				return
			}
			if len(attr) < 5+32+16 || !bytes.Equal(attr[:5], Magic[:]) {
				return
			}
			var spub [32]byte
			copy(spub[:], attr[5:37])
			var rsalt [16]byte
			copy(rsalt[:], attr[37:53])
			if rsalt != r.salt {
				return
			}
			r.completeClientHandshake(spub, now)
		}

	// client: a server-initiated consent check -> answer it
	case !r.server && r.phase == phaseData && msg.MsgType == stunBindingRequest:
		if msg.verify(packet, r.skey[:]) {
			r.lastRx = now
			rep := stunBuild(stunBindingResponse, msg.TxnID, []stunAttr{
				{Typ: AttrXorMappedAddress, Val: xorMappedAddress(r.peer.Addr(), r.peer.Port())},
			}, r.skey[:], true)
			r.wire = append(r.wire, rep)
		}
	}
}

func (r *RtcMask) completeServerHandshake(epub [32]byte, salt [16]byte, txn [12]byte, now time.Time) {
	if r.staticPriv == nil {
		return
	}
	spub, dh := r.rs.ephKeyPair()
	sharedEph := dh(epub)
	sharedStatic, err := x25519(r.staticPriv, epub[:])
	if err != nil {
		return
	}
	transcript := make([]byte, 0, 64)
	transcript = append(transcript, epub[:]...)
	transcript = append(transcript, spub[:]...)

	fc, err := kdfAuth(sharedEph, sharedStatic, salt[:], transcript)
	if err != nil {
		panic("hydra: kdf_auth: " + err.Error())
	}
	rc := mustAEAD(rtcDataKey(sharedEph, sharedStatic, salt[:], transcript))

	// reply: MAGIC || spub || salt, under the same stun key
	r.salt = salt
	r.skey = stunKey(r.staticPub[:], salt[:])
	replyVal := make([]byte, 0, len(Magic)+32+len(salt))
	replyVal = append(replyVal, Magic[:]...)
	replyVal = append(replyVal, spub[:]...)
	replyVal = append(replyVal, salt[:]...)
	rep := stunBuild(stunBindingResponse, txn, []stunAttr{
		{Typ: AttrXorMappedAddress, Val: xorMappedAddress(r.peer.Addr(), r.peer.Port())},
		{Typ: AttrOpaqueApp, Val: replyVal},
	}, r.skey[:], true)
	r.cachedPkt = append([]byte{}, rep...)
	r.wire = append(r.wire, rep)

	r.activate(now, fc, rc)
	// CONFIRM frame (counter 1), mirroring the ws handshake exactly
	r.pushFrameRaw([]byte("hydra-confirm"))
}

func (r *RtcMask) completeClientHandshake(spub [32]byte, now time.Time) {
	dh := r.clientDH
	if dh == nil {
		return // esc.take() semantics: the handshake completes only once
	}
	r.clientDH = nil
	sharedEph := dh(spub)
	sharedStatic := dh(r.staticPub)
	transcript := make([]byte, 0, 64)
	transcript = append(transcript, r.clientEpub[:]...)
	transcript = append(transcript, spub[:]...)
	fc, err := kdfAuth(sharedEph, sharedStatic, r.salt[:], transcript)
	if err != nil {
		panic("hydra: kdf_auth: " + err.Error())
	}
	rc := mustAEAD(rtcDataKey(sharedEph, sharedStatic, r.salt[:], transcript))
	// client expects the CONFIRM as frame 1, data from 2
	r.activate(now, fc, rc)
	r.framesIn = newFrameStream(fc, 1)
}

// activate performs the shared post-handshake setup (cipher instances +
// reliable channel).
func (r *RtcMask) activate(now time.Time, fc, rc cipher.AEAD) {
	r.frameCipher = fc
	r.rtcCipher = rc
	rcCipher := rc
	rs := r.rs
	r.out = newOutChannelAxis(func(counter uint64, body []byte) []byte {
		return sealMaskWith(rcCipher, counter, body, rs)
	}, r.window, r.rtoMinMs, r.rtoMaxMs)
	if r.server {
		r.framesIn = newFrameStream(fc, 1) // client data from ctr 1
	}
	r.phase = phaseData
	r.established = true
	r.lastRx = now
	r.lastKeepal = now
}

// pushFrameRaw seals + queues a frame bypassing the Connected() gate
// (handshake frames).
func (r *RtcMask) pushFrameRaw(plain []byte) {
	sealed := sealCtrPad(r.frameCipher, r.frameOutCtr, plain, r.rs, r.padCfg)
	r.frameOutCtr++
	for off := 0; off < len(sealed); off += r.chunk {
		end := off + r.chunk
		if end > len(sealed) {
			end = len(sealed)
		}
		r.pendingOut = append(r.pendingOut, append([]byte{}, sealed[off:end]...))
	}
}

func (r *RtcMask) receiveRTP(packet []byte, now time.Time) {
	if !r.established || r.rtcCipher == nil {
		return
	}
	pt := packet[1]
	isRTCP := pt >= 192 && pt <= 223
	hdr := RTPHeaderLen
	if isRTCP {
		hdr = 8
	}
	if len(packet) < hdr+NonceSize+16 {
		return
	}
	counter, body, ok := openMask(r.rtcCipher, packet[hdr:])
	if !ok {
		return // junk/corrupt: no state moved
	}
	r.lastRx = now
	if pt == 200 || counter >= keepaliveCounterBase {
		// RTCP-SR keepalive: verified, refresh liveness, nothing else
		return
	}
	if pt == 201 || counter >= ackCounterBase {
		// peer's ACK for our outgoing direction
		if len(body) >= 8 {
			upto := uint32FromBE(body[:4])
			bm := uint32FromBE(body[4:8])
			r.out.onAck(upto, bm, now)
		}
		return
	}
	if counter >= parityCounterBase {
		// Ignore authenticated legacy parity: it omits original shard lengths.
		// Original authenticated retransmissions fill gaps without ambiguity.
		return
	} else if len(body) >= 4 {
		r.input.onDataBody(body)
		if upto, bm, ok := r.input.takeAck(); ok {
			ab := make([]byte, 8)
			binaryBigEndianPutUint32(ab, upto)
			binaryBigEndianPutUint32(ab[4:], bm)
			sealed := sealMaskWith(r.rtcCipher, ackCounterBase+r.ackCounter, ab, r.rs)
			r.ackCounter++
			words := uint16((8 + len(sealed)) / 4)
			w := words - 1
			if w < 1 {
				w = 1
			}
			pkt := rtcpRR(r.ssrc, w)
			r.wire = append(r.wire, append(pkt, sealed...))
		}
	}
}

// Poll drives timers: hello retransmit, RTO retransmits, the pending queue,
// keepalives. It returns outgoing wire datagrams and decrypted frames.
func (r *RtcMask) Poll(now time.Time) RtcPoll {
	if r.dead {
		return RtcPoll{Dead: true, RotateMask: r.dpiRotate}
	}
	switch r.phase {
	case phaseHandshake:
		if !r.server && r.cachedPkt != nil && now.Sub(r.lastHello) >= helloRetry {
			r.wire = append(r.wire, append([]byte{}, r.cachedPkt...))
			r.lastHello = now
		}
	case phaseData:
		r.drainPending(now)
		for _, p := range r.out.pollRetransmit(now) {
			r.wire = append(r.wire, r.wrap(p.Counter, p.Body, now))
		}
		if now.Sub(r.lastKeepal) >= r.keepaliveEvery {
			r.lastKeepal = now
			if r.rtcCipher != nil {
				// RTCP-SR-shaped keepalive (20-byte sender-info body)
				srBody := make([]byte, 0, 20)
				srBody = binary.BigEndian.AppendUint32(srBody, r.mediaTs(now))
				ka := uint32(r.kaCounter)
				srBody = binary.BigEndian.AppendUint32(srBody, ka)
				srBody = binary.BigEndian.AppendUint32(srBody, ka)
				srBody = binary.BigEndian.AppendUint32(srBody, ka)
				srBody = binary.BigEndian.AppendUint32(srBody, ka)
				counter := keepaliveCounterBase + r.kaCounter
				r.kaCounter++
				sealed := sealMaskWith(r.rtcCipher, counter, srBody, r.rs)
				pkt := rtcpSR(r.ssrc, r.mediaTs(now), r.mediaTs(now), uint32(r.kaCounter), uint32(r.kaCounter))
				pkt = pkt[:8] // keep only the RTCP header; body = sealed
				r.wire = append(r.wire, append(pkt, sealed...))
			}
			// ICE consent-freshness check
			txn := make([]byte, 12)
			r.rs.fill(txn)
			ka := stunBuild(stunBindingRequest, asTxn12(txn), []stunAttr{
				{Typ: AttrUsername, Val: []byte(hex.EncodeToString(r.salt[:8]) + ":" + hex.EncodeToString(r.salt[8:]))},
			}, r.skey[:], true)
			r.wire = append(r.wire, ka)
		}
	}
	// ClientSelfGate sampling (dpigate.go): judge the final outgoing wire,
	// exactly the Rust run_rtc_pump poll.wire hook. A raise means the own
	// wire reads as a tunnel: dead-flag the engine so the tunnel is rebuilt
	// with a fresh mask.
	if r.dpiGate != nil {
		for _, pkt := range r.wire {
			if _, raise := r.dpiGate.Observe(pkt); raise {
				r.dpiRotate = true
				r.dead = true
			}
		}
	}
	frames := r.takeFrames()
	wire := r.wire
	r.wire = nil
	connected := r.Connected()
	dead := r.IsDead(now)
	if dead {
		r.dead = true
	}
	return RtcPoll{Wire: wire, Frames: frames, Connected: connected, Dead: dead, RotateMask: r.dpiRotate}
}

func (r *RtcMask) takeFrames() [][]byte {
	chunks := r.input.takeReady()
	if len(chunks) == 0 {
		return nil
	}
	if r.framesIn == nil {
		return nil
	}
	var frames [][]byte
	for _, c := range chunks {
		got, err := r.framesIn.feed(c)
		if err != nil || r.framesIn.bad {
			if os.Getenv("HYDRA_RTC_TRACE") != "" {
				fmt.Fprintf(os.Stderr, "rtc frame failure peer=%v phase=%d confirmed=%t ctr=%d buffered=%d chunk=%d expected=%d err=%v\n", r.peer, r.phase, r.confirmed, r.framesIn.ctr, len(r.framesIn.buf), len(c), r.input.expected, err)
			}
			r.dead = true // tamper/counter desync: fail closed
			return nil
		}
		frames = append(frames, got...)
	}
	// client: frame 1 must be the CONFIRM
	if !r.server && !r.confirmed && len(frames) > 0 {
		if bytes.Equal(frames[0], []byte("hydra-confirm")) {
			r.confirmed = true
			frames = frames[1:]
		} else {
			r.dead = true
			return nil
		}
	}
	return frames
}

// placeholderOut is the OutChannel placeholder replaced in activate once the
// RTC cipher exists.
func placeholderOut() *OutChannel {
	return newOutChannel(func(uint64, []byte) []byte { return nil })
}

func asTxn12(b []byte) [12]byte {
	var t [12]byte
	copy(t[:], b)
	return t
}

// randUint32Max1 draws a random nonzero uint32 for SSRC / timestamp origin,
// mirroring Rust rand::random::<u32>().max(1).
func randUint32Max1() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	n := binary.BigEndian.Uint32(b[:])
	if n < 1 {
		return 1
	}
	return n
}

// randUint16 draws a random uint16 for the initial RTP sequence.
func randUint16() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}
