package hydra

// Differential and engine tests for the RTC mask layer, ported from the Rust
// reference (vpns/hydra src/rtc.rs, src/reliable.rs, src/wire.rs) and checked
// against the golden vectors in testdata/rtc_vectors.txt. The vectors were
// exported by hydra tests/export_rtc_vectors.rs with:
//
//	static_priv[i] = i*2+3   static_pub = X25519(static_priv)
//	client 192.0.2.10:50000  server 192.0.2.10:443
//	timeline: hello t0, reply t0+30ms, confirm t0+60ms, data t0+100ms
//
// The Rust exporter used an OS-random ephemeral pair, so the sealed payloads
// of server-side vectors cannot be re-derived. What IS byte-exact here:
//   - every wire primitive (sha1/hmac/crc32/stun_build/xor_mapped/rtp/rtcp)
//   - the full client hello (all client randomness is recoverable from the
//     fixture by decrypting it under kdf_hello, then injected into the Go
//     engine through the test entropy seam)
//   - RTP/RTCP headers, counter fields, datagram lengths and the decrypted
//     server_frame plaintext of the data-plane vectors.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ---------------------------------------------------------------- vectors ----

func loadVectors(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rtc_vectors.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string][]string)
	for _, line := range bytes.Split(raw, []byte("\n")) {
		i := bytes.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		m[string(line[:i])] = append(m[string(line[:i])], string(line[i+1:]))
	}
	return m
}

func vec1(t *testing.T, m map[string][]string, key string) []byte {
	t.Helper()
	v, ok := m[key]
	if !ok || len(v) == 0 {
		t.Fatalf("vector %s missing", key)
	}
	return mustHex(t, v[0])
}

// fixtureStaticPair mirrors the exporter: static_priv[i] = i*2+3.
func fixtureStaticPair(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	for i := range priv {
		priv[i] = byte(i)*2 + 3
	}
	pk, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], pk)
	return priv, pub
}

var (
	fixtureClientAddr = netip.MustParseAddrPort("192.0.2.10:50000")
	fixtureServerAddr = netip.MustParseAddrPort("192.0.2.10:443")
)

// ---------------------------------------------------------------- entropy ----

// queueRand replays recorded randomness so the Go engine reproduces the exact
// bytes the Rust exporter emitted. fill/intn order must match the Rust
// constructor/seal call order exactly; ephKeyPair returns a fixed public key.
type queueRand struct {
	fills  [][]byte
	intns  []int
	ephPub [32]byte
	ephDH  func(peer [32]byte) []byte
	fi     int
	ii     int
}

func (q *queueRand) fill(p []byte) {
	if q.fi >= len(q.fills) {
		panic("queueRand: fill queue exhausted")
	}
	src := q.fills[q.fi]
	q.fi++
	if len(src) < len(p) {
		panic("queueRand: fill entry too short")
	}
	copy(p, src[:len(p)])
}

func (q *queueRand) intn(n int) int {
	if q.ii >= len(q.intns) {
		panic("queueRand: intn queue exhausted")
	}
	v := q.intns[q.ii]
	q.ii++
	if v >= n && n > 0 {
		panic("queueRand: intn out of range")
	}
	return v
}

func (q *queueRand) ephKeyPair() ([32]byte, func(peer [32]byte) []byte) {
	return q.ephPub, q.ephDH
}

// counterRand is an unbounded deterministic entropy source for Go-Go engine
// sims: position-derived fill bytes, zero padding, and a real X25519 keypair.
type counterRand struct {
	seed   byte
	scalar [32]byte
}

func newCounterRand(seed byte, scalar [32]byte) *counterRand {
	return &counterRand{seed: seed, scalar: scalar}
}

func (c *counterRand) fill(p []byte) {
	for i := range p {
		p[i] = c.seed ^ byte(i*13+7)
	}
}

func (c *counterRand) intn(n int) int { return 0 }

func (c *counterRand) ephKeyPair() ([32]byte, func(peer [32]byte) []byte) {
	return scalarEph(c.scalar)
}

// scalarEph builds a real X25519 ephemeral from a fixed scalar (clamping per
// RFC 7748), usable both as a counterRand keypair and in queueRand.
func scalarEph(scalar [32]byte) ([32]byte, func(peer [32]byte) []byte) {
	pk, err := curve25519.X25519(scalar[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	var pub [32]byte
	copy(pub[:], pk)
	s := append([]byte{}, scalar[:]...)
	return pub, func(peer [32]byte) []byte {
		shared, err := curve25519.X25519(s, peer[:])
		if err != nil {
			panic(err)
		}
		return shared
	}
}

// ---------------------------------------------------------------- helpers ----

// testSeal is the deterministic OutChannel seal used by the reliable-layer
// tests (prefix counter + body), mirroring reliable.rs unit tests.
func testSeal(counter uint64, body []byte) []byte {
	out := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint64(out, counter)
	return append(out, body...)
}

func testOpen(counter uint64, sealed []byte) []byte {
	if !bytes.Equal(sealed[:8], mustBeBytes8(counter)) {
		panic("testOpen: counter prefix mismatch")
	}
	return sealed[8:]
}

func mustBeBytes8(counter uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, counter)
	return b
}

// deliverReliable feeds one sealed packet to a receiver like rtc.rs would.
func deliverReliable(rx *InChannel, counter uint64, sealed []byte) bool {
	body := testOpen(counter, sealed)
	if len(body) >= 4 && binary.BigEndian.Uint32(body[:4]) == ParitySeq {
		return false // Legacy parity lacks shard lengths; only ARQ is supported.
	}
	return rx.onDataBody(body)
}

func chunkOf(i, length int) []byte {
	out := make([]byte, length)
	for k := range out {
		out[k] = byte((i*131 + k*7) & 0xff)
	}
	return out
}

// sim is the fake-clock datagram exchange between a Go client and server,
// mirroring rtc.rs's Sim harness.
type sim struct {
	now          time.Time
	c2s, s2c     [][]byte
	client       *RtcMask
	server       *RtcMask
	clientFrames [][]byte
	serverFrames [][]byte
	dead         bool
}

func newSim(t *testing.T) *sim {
	t.Helper()
	spriv, spub := fixtureStaticPair(t)
	clientScalar := [32]byte{}
	serverScalar := [32]byte{}
	for i := range clientScalar {
		clientScalar[i] = byte(i)*3 + 7
		serverScalar[i] = byte(i)*5 + 11
	}
	return &sim{
		now:    time.Unix(0, 0),
		client: newClientWithEntropy(spub, fixtureServerAddr, time.Unix(0, 0), newCounterRand(0xA0, clientScalar)),
		server: newServerWithEntropy(spub, spriv, fixtureClientAddr, time.Unix(0, 0), newCounterRand(0xB4, serverScalar)),
	}
}

func (s *sim) deliverC2S() {
	for _, p := range s.c2s {
		s.server.Receive(p, s.now)
	}
	s.c2s = nil
}

func (s *sim) deliverS2C() {
	for _, p := range s.s2c {
		s.client.Receive(p, s.now)
	}
	s.s2c = nil
}

func (s *sim) step(ms int) {
	s.now = s.now.Add(time.Duration(ms) * time.Millisecond)
	s.deliverC2S()
	s.deliverS2C()
	pc := s.client.Poll(s.now)
	ps := s.server.Poll(s.now)
	s.c2s = append(s.c2s, pc.Wire...)
	s.s2c = append(s.s2c, ps.Wire...)
	s.clientFrames = append(s.clientFrames, pc.Frames...)
	s.serverFrames = append(s.serverFrames, ps.Frames...)
	if pc.Dead || ps.Dead {
		s.dead = true
	}
}

// stepDropC2S advances and drops the nth client->server datagram in flight.
func (s *sim) stepDropC2S(ms int, dropNth int) {
	s.now = s.now.Add(time.Duration(ms) * time.Millisecond)
	for i, p := range s.c2s {
		if i+1 == dropNth {
			continue
		}
		s.server.Receive(p, s.now)
	}
	s.c2s = nil
	s.deliverS2C()
	pc := s.client.Poll(s.now)
	ps := s.server.Poll(s.now)
	s.c2s = append(s.c2s, pc.Wire...)
	s.s2c = append(s.s2c, ps.Wire...)
	s.clientFrames = append(s.clientFrames, pc.Frames...)
	s.serverFrames = append(s.serverFrames, ps.Frames...)
	if pc.Dead || ps.Dead {
		s.dead = true
	}
}

func (s *sim) runUntilConnected(t *testing.T, maxSteps int) {
	t.Helper()
	for i := 0; i < maxSteps; i++ {
		s.step(50)
		if s.client.Connected() && s.server.Connected() {
			return
		}
		if s.dead {
			t.Fatal("sim died during handshake")
		}
	}
	t.Fatal("handshake did not complete")
}

// drainFlight delivers everything currently queued (no polls), so a fault
// injected afterwards hits real data datagrams, not handshake leftovers.
func (s *sim) drainFlight() {
	s.deliverC2S()
	s.deliverS2C()
}

// ------------------------------------------------------------------ wire ----

// TestWirePrimitivesAgainstVectors checks the byte-exact wire primitives
// against the committed fixture (exporter lines 1-7).
func TestWirePrimitivesAgainstVectors(t *testing.T) {
	m := loadVectors(t)
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	_, staticPub := fixtureStaticPair(t)

	s1 := sha1Sum(payload)
	if got := hex.EncodeToString(s1[:]); got != string(m["sha1"][0]) {
		t.Fatalf("sha1 mismatch:\n got %s\nwant %s", got, m["sha1"][0])
	}
	hm := hmacSHA1(staticPub[:], payload)
	if got := hex.EncodeToString(hm[:]); got != string(m["hmac"][0]) {
		t.Fatalf("hmac mismatch:\n got %s\nwant %s", got, m["hmac"][0])
	}
	if got := hex.EncodeToString(crc32IEEEBytes(payload)); got != string(m["crc32"][0]) {
		t.Fatalf("crc32 mismatch:\n got %s\nwant %s", got, m["crc32"][0])
	}
	txn := bytes.Repeat([]byte{0xAA}, 12)
	stun := stunBuild(stunBindingRequest, asTxn(txn), nil, nil, true)
	if got := hex.EncodeToString(stun); got != string(m["stun_build"][0]) {
		t.Fatalf("stun_build mismatch:\n got %s\nwant %s", got, m["stun_build"][0])
	}
	xm := xorMappedAddress(fixtureClientAddr.Addr(), fixtureClientAddr.Port())
	if got := hex.EncodeToString(xm); got != string(m["xor_mapped"][0]) {
		t.Fatalf("xor_mapped mismatch:\n got %s\nwant %s", got, m["xor_mapped"][0])
	}
	rtp := rtpHeader(0x1234, 0x56789abc, 0xdeadbeef, 0x60)
	if got := hex.EncodeToString(rtp[:]); got != string(m["rtp_header"][0]) {
		t.Fatalf("rtp_header mismatch:\n got %s\nwant %s", got, m["rtp_header"][0])
	}
	sr := rtcpSR(0xdeadbeef, 1, 2, 3, 4)
	if got := hex.EncodeToString(sr); got != string(m["rtcp_sr"][0]) {
		t.Fatalf("rtcp_sr mismatch:\n got %s\nwant %s", got, m["rtcp_sr"][0])
	}
}

func asTxn(b []byte) [12]byte {
	var t [12]byte
	copy(t[:], b)
	return t
}

func crc32IEEEBytes(b []byte) []byte {
	c := crc32IEEE(b)
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, c)
	return out
}

// TestStunStrictParseAndVerify ports wire.rs's strict-parse and integrity
// checks: nDPI-grade shape gates plus MESSAGE-INTEGRITY / FINGERPRINT verify.
func TestStunStrictParseAndVerify(t *testing.T) {
	key := []byte("ice-password-hex-32-bytes-long-ok")
	txn := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	msg := stunBuild(stunBindingRequest, txn, []stunAttr{
		{Typ: AttrUsername, Val: []byte("c7f1:9a2b")},
		{Typ: AttrPriority, Val: []byte{0, 0x6E, 0x7F, 0xFF}},
		{Typ: AttrOpaqueApp, Val: []byte{0xAA, 0xBB, 0xCC}},
	}, key, true)

	parsed, ok := stunParse(msg)
	if !ok {
		t.Fatal("strict parse failed")
	}
	if parsed.MsgType != stunBindingRequest || parsed.TxnID != txn {
		t.Fatal("header fields mismatch")
	}
	if !bytes.Equal(parsed.attr(AttrUsername), []byte("c7f1:9a2b")) {
		t.Fatal("username attr mismatch")
	}
	if !bytes.Equal(parsed.attr(AttrOpaqueApp), []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatal("opaque attr mismatch")
	}
	if !parsed.verify(msg, key) {
		t.Fatal("integrity+fingerprint must verify")
	}
	if parsed.verify(msg, []byte("wrong-key-0000000000000000000")) {
		t.Fatal("wrong key must not verify")
	}

	// truncated body
	if _, ok := stunParse(msg[:len(msg)-2]); ok {
		t.Fatal("truncated message must not parse")
	}
	// broken magic
	bad := append([]byte{}, msg...)
	bad[5] = 0x99
	if _, ok := stunParse(bad); ok {
		t.Fatal("broken magic must not parse")
	}
	// non-4-aligned length
	bad2 := append([]byte{}, msg...)
	bad2[2] = 1
	if _, ok := stunParse(bad2); ok {
		t.Fatal("unaligned length must not parse")
	}
}

// TestXorMappedRoundtrip ports the v4/v6 roundtrip from wire.rs.
func TestXorMappedRoundtrip(t *testing.T) {
	v4 := netip.MustParseAddrPort("203.0.113.7:54321")
	ip, port, ok := parseXorMappedAddress(xorMappedAddress(v4.Addr(), v4.Port()))
	if !ok || !ip.IsValid() || netip.AddrPortFrom(ip, port) != v4 {
		t.Fatalf("v4 roundtrip failed: %v %v %v", ip, port, ok)
	}
	v6 := netip.MustParseAddrPort("[2001:db8::1]:3478")
	ip, port, ok = parseXorMappedAddress(xorMappedAddress(v6.Addr(), v6.Port()))
	if !ok || netip.AddrPortFrom(ip.Unmap(), port) != v6 {
		t.Fatalf("v6 roundtrip failed: %v %v %v", ip, port, ok)
	}
}

// TestRtpRtcpShapes ports the shape/demux checks from wire.rs.
func TestRtpRtcpShapes(t *testing.T) {
	h := rtpHeader(4242, 48000, 0xdeadbeef, RTPPtOpus)
	if h[0]&0xc0 != 0x80 {
		t.Fatal("rtp version bits wrong")
	}
	if h[1]&0x7f != 111 {
		t.Fatal("rtp payload type wrong")
	}
	if !bytes.Equal(h[8:12], []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatal("rtp ssrc wrong")
	}
	if got := classifyPacket(h[:]); got != "SRTP" {
		t.Fatalf("classify(rtp)=%s", got)
	}
	sr := rtcpSR(0xdeadbeef, 1234, 5, 6, 7)
	if !bytes.Equal(sr[:2], []byte{0x80, 200}) || len(sr) != 28 {
		t.Fatal("rtcp sr shape wrong")
	}
	if got := classifyPacket(sr); got != "RTCP" {
		t.Fatalf("classify(sr)=%s", got)
	}
	rr := rtcpRR(1, 3)
	if !bytes.Equal(rr[:2], []byte{0x80, 201}) {
		t.Fatal("rtcp rr shape wrong")
	}
	if got := classifyPacket([]byte{0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42}); got != "STUN" {
		t.Fatalf("classify(stun)=%s", got)
	}
	if !isRTPorRTCP(h[:]) || isRTPorRTCP([]byte{0}) {
		t.Fatal("isRTPorRTCP demux wrong")
	}
}

// ------------------------------------------------------------- reliable ----

func TestReliableInOrderRoundtrip(t *testing.T) {
	tx := newOutChannel(testSeal)
	rx := newInChannel()
	now := time.Unix(0, 0)
	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	var wire []reliablePacket
	rest := payload
	idx := 0
	for len(rest) > 0 {
		n := len(rest)
		if n > Chunk {
			n = Chunk
		}
		pkts := tx.trySend(rest[:n], now)
		if len(pkts) == 0 {
			t.Fatal("window must accept the first packets")
		}
		wire = append(wire, pkts...)
		rest = rest[n:]
		idx++
	}
	var received []byte
	for _, p := range wire {
		deliverReliable(rx, p.Counter, p.Body)
		for _, c := range rx.takeReady() {
			received = append(received, c...)
		}
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("roundtrip mismatch: got %d bytes", len(received))
	}
	upto, bm, ok := rx.takeAck()
	if !ok {
		t.Fatal("ack after delivery missing")
	}
	tx.onAck(upto, bm, now.Add(5*time.Millisecond))
	if !tx.windowFree() {
		t.Fatal("window must free after ack")
	}
}

func TestReliableOutOfOrderAndDuplicates(t *testing.T) {
	tx := newOutChannel(testSeal)
	rx := newInChannel()
	now := time.Unix(0, 0)
	var packets []reliablePacket
	for i := 0; i < 5; i++ {
		packets = append(packets, tx.trySend(chunkOf(i, 100), now)...)
	}
	for i := len(packets) - 1; i >= 0; i-- {
		deliverReliable(rx, packets[i].Counter, packets[i].Body)
	}
	deliverReliable(rx, packets[2].Counter, packets[2].Body) // duplicate
	got := 0
	for _, c := range rx.takeReady() {
		if !bytes.Equal(c, chunkOf(got, 100)) {
			t.Fatalf("chunk %d out of order", got)
		}
		got++
	}
	if got != 5 {
		t.Fatalf("delivered %d, want 5", got)
	}
}

// Legacy parity cannot safely recover variable-length shards; require ARQ.
func TestReliableSingleLossRecoveredByRTO(t *testing.T) {
	tx := newOutChannel(testSeal)
	rx := newInChannel()
	now := time.Unix(0, 0)
	var queue []reliablePacket
	for i := 0; i < 4; i++ {
		queue = append(queue, tx.trySend(chunkOf(i, 200), now)...)
	}
	for _, p := range queue {
		body := testOpen(p.Counter, p.Body)
		if binary.BigEndian.Uint32(body[:4]) == 2 {
			continue // lost
		}
		deliverReliable(rx, p.Counter, p.Body)
	}
	chunks := rx.takeReady()
	if len(chunks) != 1 {
		t.Fatalf("only seq 1 can arrive before retransmission; got %d", len(chunks))
	}
	upto, bm, _ := rx.takeAck()
	tx.onAck(upto, bm, now)
	for _, p := range tx.pollRetransmit(now.Add(600 * time.Millisecond)) {
		deliverReliable(rx, p.Counter, p.Body)
	}
	chunks = append(chunks, rx.takeReady()...)
	if len(chunks) != 4 {
		t.Fatalf("ARQ must release all four chunks; got %d", len(chunks))
	}
	for i, c := range chunks {
		if !bytes.Equal(c, chunkOf(i, 200)) {
			t.Fatalf("chunk %d wrong after repair", i)
		}
	}
	upto, bm, ok := rx.takeAck()
	if !ok || upto != 4 || bm != 0 {
		t.Fatalf("ack = (%d, %#x, %v), want (4, 0, true)", upto, bm, ok)
	}
}

func TestReliableDoubleLossFallsBackToRTO(t *testing.T) {
	tx := newOutChannel(testSeal)
	rx := newInChannel()
	now := time.Unix(0, 0)
	var queue []reliablePacket
	for i := 0; i < 4; i++ {
		queue = append(queue, tx.trySend(chunkOf(i, 50), now)...)
	}
	for _, p := range queue {
		body := testOpen(p.Counter, p.Body)
		seq := binary.BigEndian.Uint32(body[:4])
		if seq == 1 || seq == 2 {
			continue // both lost
		}
		deliverReliable(rx, p.Counter, p.Body)
	}
	if chunks := rx.takeReady(); len(chunks) != 0 {
		t.Fatalf("in-order delivery must hold until the gap fills; got %d", len(chunks))
	}
	upto, bm, ok := rx.takeAck()
	if !ok || upto != 0 {
		t.Fatalf("ack upto=%d want 0", upto)
	}
	if bm&(1<<2) == 0 {
		t.Fatal("seq 3 must be sacked (bit 2)")
	}
	if bm&(1<<3) == 0 {
		t.Fatal("seq 4 must be sacked (bit 3)")
	}
	tx.onAck(upto, bm, now)

	retrans := tx.pollRetransmit(now.Add(600 * time.Millisecond))
	if len(retrans) != 2 {
		t.Fatalf("both lost packets must be retransmitted; got %d", len(retrans))
	}
	// sort by counter (= seq order for the test seal)
	for i := 1; i < len(retrans); i++ {
		if retrans[i-1].Counter > retrans[i].Counter {
			retrans[i-1], retrans[i] = retrans[i], retrans[i-1]
		}
	}
	for _, p := range retrans {
		deliverReliable(rx, p.Counter, p.Body)
	}
	chunks := rx.takeReady()
	if len(chunks) != 4 {
		t.Fatalf("gap filled delivery must release 4 chunks; got %d", len(chunks))
	}
	for i, c := range chunks {
		if !bytes.Equal(c, chunkOf(i, 50)) {
			t.Fatalf("chunk %d wrong after RTO recovery", i)
		}
	}
}

func TestReliableWindowBackpressure(t *testing.T) {
	tx := newOutChannel(testSeal)
	rx := newInChannel()
	now := time.Unix(0, 0)
	sent := 0
	var pending []reliablePacket
	for i := 0; i < Window*3; i++ {
		pkts := tx.trySend(chunkOf(i, 10), now)
		if len(pkts) == 0 {
			break
		}
		pending = append(pending, pkts...)
		sent++
	}
	if sent > Window {
		t.Fatalf("window must cap in-flight (%d)", sent)
	}
	if tx.windowFree() {
		t.Fatal("window must be full")
	}
	for _, p := range pending {
		deliverReliable(rx, p.Counter, p.Body)
	}
	upto, bm, ok := rx.takeAck()
	if !ok {
		t.Fatal("ack missing")
	}
	tx.onAck(upto, bm, now.Add(time.Millisecond))
	if !tx.windowFree() {
		t.Fatal("ack must free the window")
	}
	if len(tx.trySend(chunkOf(9999, 10), now)) == 0 {
		t.Fatal("sending must resume after ack")
	}
}

func TestReliableRetransmitBackoffOriginalBytes(t *testing.T) {
	tx := newOutChannel(testSeal)
	rx := newInChannel()
	now := time.Unix(0, 0)
	sent := tx.trySend(chunkOf(0, 16), now)
	if len(sent) == 0 {
		t.Fatal("send failed")
	}
	c0, s0 := sent[0].Counter, sent[0].Body
	t1 := now.Add(600 * time.Millisecond)
	re1 := tx.pollRetransmit(t1)
	if len(re1) != 1 || re1[0].Counter != c0 || !bytes.Equal(re1[0].Body, s0) {
		t.Fatal("retransmit must replay original bytes")
	}
	t2 := t1.Add(600 * time.Millisecond)
	if re2 := tx.pollRetransmit(t2); len(re2) != 0 {
		t.Fatal("age reset after retransmit; rto grew")
	}
	deliverReliable(rx, c0, s0)
	upto, bm, ok := rx.takeAck()
	if !ok {
		t.Fatal("ack missing")
	}
	tx.onAck(upto, bm, t2)
	if re := tx.pollRetransmit(t2.Add(5 * time.Second)); len(re) != 0 {
		t.Fatal("ack must stop retransmits")
	}
}

func TestReliableAckBitmapSACKTail(t *testing.T) {
	tx := newOutChannel(testSeal)
	rx := newInChannel()
	now := time.Unix(0, 0)
	var pkts []reliablePacket
	for i := 0; i < 5; i++ {
		pkts = append(pkts, tx.trySend(chunkOf(i, 10), now)...)
	}
	// deliver 1,3,5 (seq 2,4 missing)
	for i, p := range pkts {
		if i == 1 || i == 3 {
			continue
		}
		deliverReliable(rx, p.Counter, p.Body)
	}
	upto, bm, ok := rx.takeAck()
	if !ok || upto != 1 {
		t.Fatalf("ack upto=%d want 1", upto)
	}
	if bm&(1<<1) == 0 {
		t.Fatal("seq 3 must be sacked (bit 1)")
	}
	if bm&(1<<0) != 0 {
		t.Fatal("seq 2 missing: must not be sacked")
	}
	if bm&(1<<3) == 0 {
		t.Fatal("seq 5 must be sacked (bit 3)")
	}
	tx.onAck(upto, bm, now)
	if re := tx.pollRetransmit(now.Add(600 * time.Millisecond)); len(re) != 2 {
		t.Fatalf("seq 2 and 4 must retransmit; got %d", len(re))
	}
}

// ---------------------------------------------------------------- engine ----

// recoverHelloFixture decrypts the fixture hello under kdf_hello and returns
// every random input the Rust client consumed, in engine call order.
func recoverHelloFixture(t *testing.T, m map[string][]string, staticPub [32]byte) (
	salt, txn, iceCtrl, epub, nonce4, pad []byte) {
	t.Helper()
	hello := vec1(t, m, "c2s_hello")
	txn = append([]byte{}, hello[8:20]...)
	msg, ok := stunParse(hello)
	if !ok {
		t.Fatal("fixture hello does not parse")
	}
	opaque := msg.attr(AttrOpaqueApp)
	if opaque == nil || len(opaque) < 16+5+32 {
		t.Fatal("fixture hello lacks OPAQUE_APP")
	}
	salt = append([]byte{}, opaque[:16]...)
	sealed := opaque[16:]
	hc, err := kdfHello(staticPub[:], salt)
	if err != nil {
		t.Fatal(err)
	}
	// openCtr strips [padLen u16][pad]; open the AEAD raw to recover the pad
	// bytes the Rust seal consumed (nonce = sealed[4:16], counter 0).
	nonce := sealed[4:16]
	ct := sealed[16:]
	inner, err := hc.Open(nil, nonce, ct, aadFor(0))
	if err != nil {
		t.Fatalf("fixture hello decrypt failed: %v", err)
	}
	nonce4 = append([]byte{}, sealed[4:8]...)
	if len(inner) < 2 || len(inner) < 2+int(binary.BigEndian.Uint16(inner)) {
		t.Fatal("fixture hello inner malformed")
	}
	padLen := int(binary.BigEndian.Uint16(inner))
	pad = inner[2 : 2+padLen]
	payload := inner[2+padLen:]
	if !bytes.Equal(payload[:5], Magic[:]) {
		t.Fatal("fixture hello inner magic mismatch")
	}
	epub = append([]byte{}, payload[5:37]...)
	iceCtrl = append([]byte{}, msg.attr(AttrIceControlling)...)
	return salt, txn, iceCtrl, epub, nonce4, pad
}

// TestClientHelloByteExactAgainstVector drives the Go client with the exact
// randomness the Rust exporter consumed and requires the constructor hello to
// equal the committed c2s_hello vector byte for byte.
func TestClientHelloByteExactAgainstVector(t *testing.T) {
	m := loadVectors(t)
	_, staticPub := fixtureStaticPair(t)
	salt, txn, iceCtrl, epub, nonce4, pad := recoverHelloFixture(t, m, staticPub)

	q := &queueRand{
		fills: [][]byte{salt, nonce4, pad, txn[:], iceCtrl[:]},
		intns: []int{len(pad)},
	}
	copy(q.ephPub[:], epub)

	c := newClientWithEntropy(staticPub, fixtureServerAddr, time.Unix(0, 0), q)
	pc := c.Poll(time.Unix(0, 0))
	if len(pc.Wire) != 1 {
		t.Fatalf("client poll must emit exactly the hello; got %d datagrams", len(pc.Wire))
	}
	want := vec1(t, m, "c2s_hello")
	if !bytes.Equal(pc.Wire[0], want) {
		got := pc.Wire[0]
		t.Fatalf("client hello mismatch:\n got (%d B) %x\nwant (%d B) %x", len(got), got, len(want), want)
	}
}

// TestServerReplyStructureAgainstVector feeds the fixture hello to the Go
// server and checks the reply against the s2c_stun_reply vector: header, txn
// echo, XOR-MAPPED value, salt echo, attribute layout and total length. The
// server ephemeral (and therefore OPAQUE pub / MI / FINGERPRINT values) cannot
// be reproduced from the fixture — the Rust exporter used an OS-random
// ephemeral whose secret is unrecoverable.
func TestServerReplyStructureAgainstVector(t *testing.T) {
	m := loadVectors(t)
	spriv, spub := fixtureStaticPair(t)
	hello := vec1(t, m, "c2s_hello")

	s := newServerWithEntropy(spub, spriv, fixtureClientAddr, time.Unix(0, 0), newCounterRand(0xB4, [32]byte{}))
	s.Receive(hello, time.Unix(0, 0))
	ps := s.Poll(time.Unix(0, 0).Add(30 * time.Millisecond))
	if len(ps.Wire) != 2 {
		t.Fatalf("server poll must emit reply + confirm; got %d", len(ps.Wire))
	}
	reply := ps.Wire[0]
	want := vec1(t, m, "s2c_stun_reply")

	if !bytes.Equal(reply[:8], want[:8]) {
		t.Fatalf("reply header mismatch:\n got %x\nwant %x", reply[:8], want[:8])
	}
	if len(reply) != len(want) {
		t.Fatalf("reply length %d, want %d", len(reply), len(want))
	}
	msg, ok := stunParse(reply)
	if !ok {
		t.Fatal("Go reply does not strict-parse")
	}
	wantMsg, ok := stunParse(want)
	if !ok {
		t.Fatal("fixture reply does not parse")
	}
	if msg.TxnID != wantMsg.TxnID {
		t.Fatal("txn echo mismatch")
	}
	// attribute (type, len) layout must match the vector exactly
	for i := range msg.Attrs {
		if msg.Attrs[i].Typ != wantMsg.Attrs[i].Typ || len(msg.Attrs[i].Val) != len(wantMsg.Attrs[i].Val) {
			t.Fatalf("attr %d: got (%#x,%d) want (%#x,%d)",
				i, msg.Attrs[i].Typ, len(msg.Attrs[i].Val), wantMsg.Attrs[i].Typ, len(wantMsg.Attrs[i].Val))
		}
	}
	// XOR-MAPPED value must be byte-exact (same peer address)
	gotXM := msg.attr(AttrXorMappedAddress)
	wantXM := wantMsg.attr(AttrXorMappedAddress)
	if !bytes.Equal(gotXM, wantXM) {
		t.Fatalf("xor-mapped mismatch:\n got %x\nwant %x", gotXM, wantXM)
	}
	ip, port, ok := parseXorMappedAddress(gotXM)
	if !ok || netip.AddrPortFrom(ip, port) != fixtureClientAddr {
		t.Fatalf("xor-mapped does not decode to %v (got %v:%d)", fixtureClientAddr, ip, port)
	}
	// OPAQUE: magic + salt echo must match; the ephemeral pub legitimately differs
	gotOP := msg.attr(AttrOpaqueApp)
	wantOP := wantMsg.attr(AttrOpaqueApp)
	if !bytes.Equal(gotOP[:5], wantOP[:5]) {
		t.Fatal("reply opaque magic mismatch")
	}
	if !bytes.Equal(gotOP[37:53], wantOP[37:53]) {
		t.Fatal("reply salt echo mismatch")
	}
	// integrity must verify under the stun key derived from the fixture salt
	hf, ok := stunParse(hello)
	if !ok {
		t.Fatal("fixture hello does not parse")
	}
	salt := hf.attr(AttrOpaqueApp)[:16]
	skey := stunKey(spub[:], salt)
	if !msg.verify(reply, skey[:]) {
		t.Fatal("Go reply MI/FINGERPRINT must verify under the fixture stun key")
	}
	if got := classifyPacket(reply); got != "STUN" {
		t.Fatalf("reply classify = %s", got)
	}
	// the confirm datagram must be RTP-shaped with PT 111
	confirm := ps.Wire[1]
	if got := classifyPacket(confirm); got != "SRTP" {
		t.Fatalf("confirm classify = %s", got)
	}
	if confirm[1]&0x7f != RTPPtOpus {
		t.Fatalf("confirm PT = %d, want %d", confirm[1]&0x7f, RTPPtOpus)
	}
}

// TestDataPlaneDifferential1150 drives the exporter timeline end to end with
// a Go client + Go server, injecting the fixture's cosmetic values (RTP seq,
// timestamp origin, SSRC) and the timeline that produced the vectors. The
// 1150-byte frame must produce exactly two c2s datagrams whose RTP headers,
// counters and lengths match the vectors, the server must decrypt exactly one
// frame equal to the server_frame vector, and the RTCP-RR ACKs must match the
// s2c_ack vector headers and counters.
func TestDataPlaneDifferential1150(t *testing.T) {
	m := loadVectors(t)
	spriv, spub := fixtureStaticPair(t)
	confirmVec := vec1(t, m, "s2c_confirm")
	dataVecs := m["c2s_data"]
	ackVecs := m["s2c_ack"]
	if len(dataVecs) != 2 || len(ackVecs) != 2 {
		t.Fatalf("fixture must hold 2 c2s_data + 2 s2c_ack vectors")
	}
	d0 := mustHex(t, dataVecs[0])
	d1 := mustHex(t, dataVecs[1])

	clientScalar := [32]byte{}
	serverScalar := [32]byte{}
	for i := range clientScalar {
		clientScalar[i] = byte(i)*3 + 7
		serverScalar[i] = byte(i)*5 + 11
	}
	// Client entropy queue. The Rust exporter drew pad=20 for the 1150-byte
	// frame (visible as the tail-datagram length delta), so the frame-seal
	// intn must replay 20; the hello pad is a free choice (0). Fills follow
	// the engine's exact call order: salt, hello nonce, txn, ICE-CTRL, ACK
	// nonce, frame nonce, pad bytes, two chunk mask nonces.
	clientRand := &queueRand{
		fills: [][]byte{
			bytes.Repeat([]byte{0xA0}, 16), // salt
			{0x11, 0x22, 0x33, 0x44},       // hello nonce prefix
			bytes.Repeat([]byte{0xB0}, 12), // txn
			bytes.Repeat([]byte{0xC0}, 8),  // ICE-CONTROLLING
			{0x55, 0x66, 0x77, 0x88},       // client ACK nonce
			{0x99, 0xaa, 0xbb, 0xcc},       // frame seal nonce
			bytes.Repeat([]byte{0xDD}, 20), // frame pad bytes
			{0x1, 0x2, 0x3, 0x4},           // chunk 1 mask nonce
			{0x5, 0x6, 0x7, 0x8},           // chunk 2 mask nonce
		},
		intns: []int{0, 20},
	}
	clientRand.ephPub, clientRand.ephDH = scalarEph(clientScalar)
	t0 := time.Unix(0, 0)
	c := newClientWithEntropy(spub, fixtureServerAddr, t0, clientRand)
	s := newServerWithEntropy(spub, spriv, fixtureClientAddr, t0, newCounterRand(0xB4, serverScalar))

	// inject the cosmetics the exporter run happened to draw
	c.ssrc = binary.BigEndian.Uint32(d0[8:12])
	c.rtpSeq = binary.BigEndian.Uint16(d0[2:4])
	c.tsOrigin = binary.BigEndian.Uint32(d0[4:8]) - 4800 // data poll at t0+100ms
	s.ssrc = binary.BigEndian.Uint32(confirmVec[8:12])
	s.rtpSeq = binary.BigEndian.Uint16(confirmVec[2:4])
	s.tsOrigin = binary.BigEndian.Uint32(confirmVec[4:8]) - 1440 // confirm at t0+30ms

	// hello -> server
	pc := c.Poll(t0)
	if len(pc.Wire) != 1 {
		t.Fatalf("client must emit one hello; got %d", len(pc.Wire))
	}
	s.Receive(pc.Wire[0], t0)

	// reply + confirm
	t1 := t0.Add(30 * time.Millisecond)
	ps := s.Poll(t1)
	if len(ps.Wire) != 2 {
		t.Fatalf("server must emit reply + confirm; got %d", len(ps.Wire))
	}
	c.Receive(ps.Wire[0], t1)

	// confirm in its own datagram cycle
	t2 := t1.Add(30 * time.Millisecond)
	c.Receive(ps.Wire[1], t2)
	pc = c.Poll(t2)
	if !pc.Connected {
		t.Fatal("client must be connected after consuming the confirm")
	}
	if len(pc.Frames) != 0 {
		t.Fatalf("confirm must never leak as an app frame; got %d", len(pc.Frames))
	}

	t3 := t2.Add(30 * time.Millisecond)
	if pc := c.Poll(t3); !pc.Connected {
		t.Fatal("connected state must hold")
	}

	// the 1150-byte body from the exporter
	body := make([]byte, 1150)
	for i := range body {
		body[i] = byte(i % 251)
	}
	c.SendFrame(body)
	t4 := t3.Add(10 * time.Millisecond)
	pc = c.Poll(t4)
	if len(pc.Wire) != 2 {
		t.Fatalf("poll must emit exactly two c2s_data datagrams; got %d", len(pc.Wire))
	}
	for i, dg := range pc.Wire {
		want := d0
		if i == 1 {
			want = d1
		}
		if len(dg) != len(want) {
			t.Fatalf("datagram %d length %d, want %d (chunking/padding arithmetic)", i, len(dg), len(want))
		}
		if !bytes.Equal(dg[:12], want[:12]) {
			t.Fatalf("datagram %d RTP header mismatch:\n got %x\nwant %x", i, dg[:12], want[:12])
		}
		// nonce counter half is deterministic: DATA_COUNTER_BASE + seq
		if !bytes.Equal(dg[16:24], want[16:24]) {
			t.Fatalf("datagram %d counter mismatch:\n got %x\nwant %x", i, dg[16:24], want[16:24])
		}
		if got := classifyPacket(dg); got != "SRTP" {
			t.Fatalf("datagram %d classify = %s", i, got)
		}
	}

	// server decodes exactly one frame == server_frame vector
	s.Receive(pc.Wire[0], t4)
	s.Receive(pc.Wire[1], t4)
	ps = s.Poll(t4)
	if len(ps.Frames) != 1 {
		t.Fatalf("server must decrypt exactly one app frame; got %d", len(ps.Frames))
	}
	serverFrame := vec1(t, m, "server_frame")
	if !bytes.Equal(ps.Frames[0], serverFrame) {
		t.Fatalf("server frame mismatch:\n got %d B\nwant %d B", len(ps.Frames[0]), len(serverFrame))
	}

	// ACKs: RTCP-RR shaped, headers + counters byte-exact against the vectors
	if len(ps.Wire) != 2 {
		t.Fatalf("server must emit two ACKs; got %d", len(ps.Wire))
	}
	for i, ack := range ps.Wire {
		want := mustHex(t, ackVecs[i])
		if len(ack) != len(want) {
			t.Fatalf("ack %d length %d, want %d", i, len(ack), len(want))
		}
		if !bytes.Equal(ack[:8], want[:8]) {
			t.Fatalf("ack %d RTCP header mismatch:\n got %x\nwant %x", i, ack[:8], want[:8])
		}
		if !bytes.Equal(ack[12:20], want[12:20]) {
			t.Fatalf("ack %d counter mismatch:\n got %x\nwant %x", i, ack[12:20], want[12:20])
		}
		if got := classifyPacket(ack); got != "RTCP" {
			t.Fatalf("ack %d classify = %s", i, got)
		}
	}

	// feeding the ACKs must free the client window
	for _, ack := range ps.Wire {
		c.Receive(ack, t4)
	}
	if !c.out.windowFree() {
		t.Fatal("client window must free after ACKs")
	}
}

// TestEngineHandshakeSimAndFrames runs the full Go-Go sim: handshake, confirm
// gating, bidirectional frames, and a large multi-chunk frame each way.
func TestEngineHandshakeSimAndFrames(t *testing.T) {
	s := newSim(t)
	s.runUntilConnected(t, 200)
	if len(s.clientFrames) != 0 || len(s.serverFrames) != 0 {
		t.Fatal("no app frames expected after handshake")
	}

	s.client.SendFrame([]byte("open-req"))
	s.server.SendFrame([]byte("open-reply"))
	for i := 0; i < 20; i++ {
		s.step(20)
	}
	if len(s.serverFrames) == 0 || !bytes.Equal(s.serverFrames[0], []byte("open-req")) {
		t.Fatalf("server frames: %d", len(s.serverFrames))
	}
	if len(s.clientFrames) == 0 || !bytes.Equal(s.clientFrames[0], []byte("open-reply")) {
		t.Fatalf("client frames: %d", len(s.clientFrames))
	}
	s.serverFrames = s.serverFrames[1:]
	s.clientFrames = s.clientFrames[1:]

	big := make([]byte, 20000)
	for i := range big {
		big[i] = byte(i % 251)
	}
	s.client.SendFrame(big)
	s.server.SendFrame(big)
	for i := 0; i < 300; i++ {
		s.step(10)
		if len(s.clientFrames) > 0 && len(s.serverFrames) > 0 {
			break
		}
	}
	if len(s.serverFrames) == 0 || !bytes.Equal(s.serverFrames[0], big) {
		t.Fatalf("big frame to server mismatch (%d frames)", len(s.serverFrames))
	}
	if len(s.clientFrames) == 0 || !bytes.Equal(s.clientFrames[0], big) {
		t.Fatalf("big frame to client mismatch (%d frames)", len(s.clientFrames))
	}
}

// TestEngineSingleLossRTORecovery replaces unsafe legacy FEC expectations.
// A lost original must be retransmitted without emitting ambiguous parity.
func TestEngineSingleLossRTORecovery(t *testing.T) {
	s := newSim(t)
	s.runUntilConnected(t, 200)
	s.drainFlight()
	big := make([]byte, 5000)
	for i := range big {
		big[i] = byte(i * 3 % 256)
	}
	s.client.SendFrame(big)
	pc := s.client.Poll(s.now) // emit the data datagrams
	// Legacy parity is unsupported because it omits original shard lengths.
	parityCount := 0
	for _, dg := range pc.Wire {
		if len(dg) >= 2 && dg[1]&0x7f == RTPPtFec {
			parityCount++
		}
	}
	if parityCount != 0 {
		t.Fatalf("unsafe legacy parity emitted: %d", parityCount)
	}
	for i, dg := range pc.Wire {
		if i == 0 {
			continue // lost: the first data datagram
		}
		s.server.Receive(dg, s.now)
	}
	for i := 0; i < 400; i++ {
		s.step(15)
		if len(s.serverFrames) > 0 {
			break
		}
	}
	if len(s.serverFrames) == 0 {
		t.Fatal("RTO must repair a single loss")
	}
	if !bytes.Equal(s.serverFrames[0], big) {
		t.Fatal("RTO-repaired frame must be byte-exact")
	}
}

// TestEngineDoubleLossRTORecovery drops the first two data datagrams of one
// FEC group (parity cannot repair two losses) and requires the RTO
// retransmit to repair, under the fake clock.
func TestEngineDoubleLossRTORecovery(t *testing.T) {
	s := newSim(t)
	s.runUntilConnected(t, 200)
	s.drainFlight()
	big := make([]byte, 5000)
	for i := range big {
		big[i] = byte(i * 5 % 256)
	}
	s.client.SendFrame(big)
	pc := s.client.Poll(s.now) // emit the data datagrams
	for i, dg := range pc.Wire {
		if i == 0 || i == 1 {
			continue // two losses inside group 1: parity defeated
		}
		s.server.Receive(dg, s.now)
	}
	arrivedAt := time.Duration(0)
	for i := 0; i < 600; i++ {
		s.step(20)
		if len(s.serverFrames) > 0 {
			arrivedAt = time.Duration(i+1) * 20 * time.Millisecond
			break
		}
		if s.dead {
			t.Fatal("sim died waiting for RTO recovery")
		}
	}
	if len(s.serverFrames) == 0 {
		t.Fatal("RTO must repair a double loss")
	}
	if !bytes.Equal(s.serverFrames[0], big) {
		t.Fatal("RTO-repaired frame must be byte-exact")
	}
	if arrivedAt < 250*time.Millisecond {
		t.Fatalf("frame arrived at %v before any RTO could fire (250ms)", arrivedAt)
	}
}

// TestEngineJunkNeverEstablishes ports rtc.rs's junk flood: garbage, a
// structurally valid STUN with the wrong key, and a forged request must never
// allocate handshake state, produce frames, or kill the endpoint.
func TestEngineJunkNeverEstablishes(t *testing.T) {
	spriv, spub := fixtureStaticPair(t)
	now := time.Unix(0, 0)
	s := newServerWithEntropy(spub, spriv, fixtureClientAddr, now, newCounterRand(0xB4, [32]byte{}))

	junk := make([]byte, 700)
	for i := 0; i < 300; i++ {
		n := 400 + i%600
		if n > len(junk) {
			junk = make([]byte, n)
		}
		junk = junk[:n]
		for j := range junk {
			junk[j] = byte(i) ^ 0x5A
		}
		switch i % 3 {
		case 0:
			junk[0] = 0x00
		case 1:
			junk[0] = 0x80
		default:
			junk[0] = 0xFF
		}
		s.Receive(junk, now)
	}
	// structurally valid STUN shape with WRONG integrity
	bad := make([]byte, 60)
	bad[0] = 0x00
	bad[1] = 0x01
	copy(bad[4:8], stunMagic[:])
	s.Receive(bad, now)
	// forged request from a peer without the static-pub capability
	forged := stunBuild(stunBindingRequest, [12]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}, []stunAttr{
		{Typ: AttrOpaqueApp, Val: append(make([]byte, 16), bytes.Repeat([]byte{1}, 53)...)},
	}, []byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}, true)
	s.Receive(forged, now)

	for i := 0; i < 20; i++ {
		now = now.Add(50 * time.Millisecond)
		poll := s.Poll(now)
		if s.established {
			t.Fatal("junk must never complete a handshake")
		}
		if len(poll.Frames) != 0 {
			t.Fatal("junk must never produce frames")
		}
		if poll.Dead {
			t.Fatal("junk must not kill the endpoint pre-timeout")
		}
	}
}

// TestEngineHandshakeTimeout ports the handshake-timeout check.
func TestEngineHandshakeTimeout(t *testing.T) {
	_, spub := fixtureStaticPair(t)
	t0 := time.Unix(0, 0)
	c := newClientWithEntropy(spub, fixtureServerAddr, t0, newCounterRand(0xA0, [32]byte{}))
	if c.IsDead(t0.Add(5 * time.Second)) {
		t.Fatal("5s handshake wait is fine")
	}
	if !c.IsDead(t0.Add(rtcHandshakeTimeout + time.Second)) {
		t.Fatal("handshake must time out")
	}
}

// TestEngineDuplicateHelloResendsCachedReply covers the NAT-rebinding path:
// a duplicate hello arriving after the server is established (our reply was
// lost) must re-send the cached reply datagram, not allocate new state.
func TestEngineDuplicateHelloResendsCachedReply(t *testing.T) {
	s := newSim(t)
	s.runUntilConnected(t, 200)
	s.drainFlight()

	// recover the original hello from the client's cached packet
	hello := s.client.cachedPkt
	if hello == nil {
		t.Fatal("client must cache its hello")
	}
	s.server.Receive(hello, s.now)
	ps := s.server.Poll(s.now)
	if len(ps.Wire) != 1 {
		t.Fatalf("duplicate hello must re-send exactly the cached reply; got %d", len(ps.Wire))
	}
	if got := classifyPacket(ps.Wire[0]); got != "STUN" {
		t.Fatalf("cached reply classify = %s", got)
	}
	// and a duplicate hello with a DIFFERENT salt must be ignored entirely
	s2 := newSim(t)
	s2.runUntilConnected(t, 200)
	s2.drainFlight()
	h := append([]byte{}, s2.client.cachedPkt...)
	h[len(h)-40] ^= 0xff // corrupt a byte inside the hello attr
	s2.server.Receive(h, s2.now)
	ps = s2.server.Poll(s2.now)
	if len(ps.Wire) != 0 {
		t.Fatalf("tampered duplicate hello must be ignored; got %d datagrams", len(ps.Wire))
	}
}
