package hydra

// Per-candidate RTC axes (axis-sweep waves 2 + 4): unit/vector tests for
// RtcChannelParams — chunk (B1), window (B2), RTO bounds (D1), buffer cap
// (D2), keepalive cadence (D3) — and the pad axis in rtc.go (padTargetWith
// buckets / MAX_PAD / big-frame bound).
//
// Contract:
//   - RtcChannelParams{} (all zero) is byte-identical to the pre-axes engine
//     (chunk 1150, window 128, rto 250/3000 ms, buffer 512, keepalive 5 s,
//     buckets {256,1024,4096,16384,65536}, MaxPad 64, big-frame 4096).
//   - normalize() clamps/validates: out-of-range catalogue values can never
//     push the engine outside wire-safe bounds.
//   - Coupling follows audit F5 (corrected): the receiver is LENGTH-AGNOSTIC.
//     A chunk/window mismatch between endpoints must NOT break framing —
//     matched values are catalogue policy (server env must match), not a
//     protocol requirement. There is deliberately no must-fail negative test;
//     the mismatch round-trip below must SUCCEED.

import (
	"bytes"
	"testing"
	"time"
)

// axisMaxRand draws the maximum of every range, so pad lengths become
// deterministic upper bounds.
type axisMaxRand struct{}

func (axisMaxRand) fill(p []byte) {
	for i := range p {
		p[i] = 0xA5
	}
}

func (axisMaxRand) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return n
}

func (axisMaxRand) ephKeyPair() ([32]byte, func([32]byte) []byte) {
	return [32]byte{}, nil
}

func TestRtcChannelDefaultsByteIdentical(t *testing.T) {
	n := RtcChannelParams{}.normalize()
	if n.Chunk != 1150 {
		t.Fatalf("default Chunk = %d, want 1150", n.Chunk)
	}
	if n.Window != 128 {
		t.Fatalf("default Window = %d, want 128", n.Window)
	}
	if n.RtoMinMs != 250.0 || n.RtoMaxMs != 3000.0 {
		t.Fatalf("default RTO = %v/%v, want 250/3000", n.RtoMinMs, n.RtoMaxMs)
	}
	if n.BufferCap != 512 {
		t.Fatalf("default BufferCap = %d, want 512", n.BufferCap)
	}
	if n.KeepaliveEvery != 5*time.Second {
		t.Fatalf("default KeepaliveEvery = %v, want 5s", n.KeepaliveEvery)
	}
	if n.MaxPad != MaxPad {
		t.Fatalf("default MaxPad = %d, want MaxPad (%d)", n.MaxPad, MaxPad)
	}
	if n.BigFramePadMax != 4096 {
		t.Fatalf("default BigFramePadMax = %d, want 4096", n.BigFramePadMax)
	}
	want := []int{256, 1024, 4096, 16384, 65536}
	if len(n.PadBuckets) != len(want) {
		t.Fatalf("default PadBuckets = %v, want %v", n.PadBuckets, want)
	}
	for i := range want {
		if n.PadBuckets[i] != want[i] {
			t.Fatalf("default PadBuckets[%d] = %d, want %d", i, n.PadBuckets[i], want[i])
		}
	}
	// normalize is idempotent.
	again := n.normalize()
	if again.Chunk != n.Chunk || again.Window != n.Window || again.RtoMinMs != n.RtoMinMs ||
		again.RtoMaxMs != n.RtoMaxMs || again.BufferCap != n.BufferCap ||
		again.KeepaliveEvery != n.KeepaliveEvery || again.MaxPad != n.MaxPad ||
		again.BigFramePadMax != n.BigFramePadMax || len(again.PadBuckets) != len(want) {
		t.Fatalf("normalize not idempotent: %+v", again)
	}
	// The engine constructor paths apply the same defaults.
	spriv, spub := fixtureStaticPair(t)
	c := newClientWithEntropyParams(spub, fixtureServerAddr, time.Unix(0, 0), newCounterRand(0xA0, [32]byte{}), RtcChannelParams{})
	if c.chunk != 1150 || c.window != 128 || c.keepaliveEvery != 5*time.Second ||
		c.rtoMinMs != 250 || c.rtoMaxMs != 3000 || c.padCfg.maxPad != MaxPad || c.padCfg.bigPad != 4096 {
		t.Fatalf("client constructor defaults drifted: chunk=%d window=%d ka=%v rto=%v/%v maxPad=%d bigPad=%d",
			c.chunk, c.window, c.keepaliveEvery, c.rtoMinMs, c.rtoMaxMs, c.padCfg.maxPad, c.padCfg.bigPad)
	}
	s := newServerWithEntropyParams(spub, spriv, fixtureClientAddr, time.Unix(0, 0), newCounterRand(0xB4, [32]byte{}), RtcChannelParams{})
	if s.chunk != 1150 || s.window != 128 || s.keepaliveEvery != 5*time.Second {
		t.Fatalf("server constructor defaults drifted")
	}
}

func TestRtcChannelClamps(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*RtcChannelParams)
		check func(RtcChannelParams) bool
	}{
		{"chunk zero default", func(p *RtcChannelParams) { p.Chunk = 0 }, func(n RtcChannelParams) bool { return n.Chunk == 1150 }},
		{"chunk below lo", func(p *RtcChannelParams) { p.Chunk = 100 }, func(n RtcChannelParams) bool { return n.Chunk == 256 }},
		{"chunk above hi", func(p *RtcChannelParams) { p.Chunk = 1 << 16 }, func(n RtcChannelParams) bool { return n.Chunk == 1180 }},
		{"chunk hi edge", func(p *RtcChannelParams) { p.Chunk = 1180 }, func(n RtcChannelParams) bool { return n.Chunk == 1180 }},
		{"window zero default", func(p *RtcChannelParams) { p.Window = 0 }, func(n RtcChannelParams) bool { return n.Window == 128 }},
		{"window below lo", func(p *RtcChannelParams) { p.Window = 5 }, func(n RtcChannelParams) bool { return n.Window == 16 }},
		{"window above hi", func(p *RtcChannelParams) { p.Window = 4096 }, func(n RtcChannelParams) bool { return n.Window == 1024 }},
		{"rto min zero default", func(p *RtcChannelParams) { p.RtoMinMs = 0 }, func(n RtcChannelParams) bool { return n.RtoMinMs == 250 }},
		{"rto min below lo", func(p *RtcChannelParams) { p.RtoMinMs = 1 }, func(n RtcChannelParams) bool { return n.RtoMinMs == 50 }},
		{"rto min above hi", func(p *RtcChannelParams) { p.RtoMinMs = 900 }, func(n RtcChannelParams) bool { return n.RtoMinMs == 500 }},
		{"rto max zero default", func(p *RtcChannelParams) { p.RtoMaxMs = 0 }, func(n RtcChannelParams) bool { return n.RtoMaxMs == 3000 }},
		{"rto max below lo", func(p *RtcChannelParams) { p.RtoMaxMs = 500 }, func(n RtcChannelParams) bool { return n.RtoMaxMs == 1000 }},
		{"rto max above hi", func(p *RtcChannelParams) { p.RtoMaxMs = 60000 }, func(n RtcChannelParams) bool { return n.RtoMaxMs == 10000 }},
		{"buffer zero default", func(p *RtcChannelParams) { p.BufferCap = 0 }, func(n RtcChannelParams) bool { return n.BufferCap == 512 }},
		{"buffer below lo", func(p *RtcChannelParams) { p.BufferCap = 1 }, func(n RtcChannelParams) bool { return n.BufferCap == 128 }},
		{"buffer above hi", func(p *RtcChannelParams) { p.BufferCap = 100000 }, func(n RtcChannelParams) bool { return n.BufferCap == 2048 }},
		{"keepalive zero default", func(p *RtcChannelParams) { p.KeepaliveEvery = 0 }, func(n RtcChannelParams) bool { return n.KeepaliveEvery == 5*time.Second }},
		{"keepalive below lo", func(p *RtcChannelParams) { p.KeepaliveEvery = time.Second }, func(n RtcChannelParams) bool { return n.KeepaliveEvery == 2*time.Second }},
		{"keepalive above hi", func(p *RtcChannelParams) { p.KeepaliveEvery = time.Hour }, func(n RtcChannelParams) bool { return n.KeepaliveEvery == 15*time.Second }},
		{"maxpad zero default", func(p *RtcChannelParams) { p.MaxPad = 0 }, func(n RtcChannelParams) bool { return n.MaxPad == 64 }},
		{"maxpad above hi", func(p *RtcChannelParams) { p.MaxPad = 9999 }, func(n RtcChannelParams) bool { return n.MaxPad == 64 }},
		{"maxpad negative", func(p *RtcChannelParams) { p.MaxPad = -5 }, func(n RtcChannelParams) bool { return n.MaxPad == 0 }},
		{"bigpad zero default", func(p *RtcChannelParams) { p.BigFramePadMax = 0 }, func(n RtcChannelParams) bool { return n.BigFramePadMax == 4096 }},
		{"bigpad above hi", func(p *RtcChannelParams) { p.BigFramePadMax = 99999 }, func(n RtcChannelParams) bool { return n.BigFramePadMax == 4096 }},
		{"bigpad negative", func(p *RtcChannelParams) { p.BigFramePadMax = -1 }, func(n RtcChannelParams) bool { return n.BigFramePadMax == 0 }},
	}
	for _, tc := range cases {
		in := RtcChannelParams{}
		tc.mut(&in)
		got := in.normalize()
		if !tc.check(got) {
			t.Fatalf("%s: normalized = %+v", tc.name, got)
		}
	}
	// Clamp ranges guarantee rtoMin <= rtoMax after normalization for ANY input.
	for _, m := range []float64{-100, 0, 50, 250, 500, 499.9, 1e9} {
		for _, x := range []float64{-100, 0, 1000, 3000, 10000, 9999.9, 1e12} {
			p := RtcChannelParams{RtoMinMs: m, RtoMaxMs: x}
			n := p.normalize()
			if n.RtoMinMs > n.RtoMaxMs {
				t.Fatalf("rto ordering violated for %v/%v: %v/%v", m, x, n.RtoMinMs, n.RtoMaxMs)
			}
		}
	}
}

func TestRtcChannelPadBucketValidation(t *testing.T) {
	def := []int{256, 1024, 4096, 16384, 65536}
	bad := [][]int{
		nil,
		{},
		{1024, 256}, // not ascending
		{256, 256},  // duplicate
		{128},       // below 256
		{131072},    // above 65536
		{256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}, // nine buckets
	}
	for _, b := range bad {
		p := RtcChannelParams{PadBuckets: b}
		got := p.normalize()
		if len(got.PadBuckets) != len(def) {
			t.Fatalf("invalid buckets %v accepted: got %v", b, got.PadBuckets)
		}
		for i := range def {
			if got.PadBuckets[i] != def[i] {
				t.Fatalf("invalid buckets %v: got %v, want default", b, got.PadBuckets)
			}
		}
	}
	good := []int{512, 2048}
	got := RtcChannelParams{PadBuckets: good}.normalize()
	if len(got.PadBuckets) != 2 || got.PadBuckets[0] != 512 || got.PadBuckets[1] != 2048 {
		t.Fatalf("valid custom buckets not preserved: %v", got.PadBuckets)
	}
	if &got.PadBuckets[0] == &good[0] {
		t.Fatalf("normalize must copy the bucket slice, got alias")
	}
	// Eight ascending buckets are allowed.
	eight := []int{256, 512, 1024, 2048, 4096, 8192, 16384, 32768}
	got = RtcChannelParams{PadBuckets: eight}.normalize()
	if len(got.PadBuckets) != 8 {
		t.Fatalf("eight-bucket set rejected: %v", got.PadBuckets)
	}
}

func TestOutChannelWindowAxis(t *testing.T) {
	n := RtcChannelParams{Window: 16}.normalize()
	tx := newOutChannelAxis(testSeal, n.Window, n.RtoMinMs, n.RtoMaxMs)
	t0 := time.Unix(0, 0)
	sent := 0
	for i := 0; i < 100; i++ {
		if pkts := tx.trySend(chunkOf(i, 10), t0); len(pkts) == 1 {
			sent++
		}
	}
	if sent != 16 {
		t.Fatalf("window axis: sent %d packets before window full, want 16", sent)
	}
	if tx.windowFree() {
		t.Fatalf("windowFree must be false at capacity")
	}
	// Default path (legacy constructors) unchanged: Window const.
	txDef := newOutChannel(testSeal)
	sent = 0
	for i := 0; i < Window+10; i++ {
		if pkts := txDef.trySend(chunkOf(i, 10), t0); len(pkts) == 1 {
			sent++
		}
	}
	if sent != Window {
		t.Fatalf("default window: sent %d, want %d", sent, Window)
	}
}

func TestOutChannelRtoAxis(t *testing.T) {
	n := RtcChannelParams{RtoMinMs: 50, RtoMaxMs: 1000}.normalize()
	tx := newOutChannelAxis(testSeal, Window, n.RtoMinMs, n.RtoMaxMs)
	t0 := time.Unix(0, 0)
	if pkts := tx.trySend(chunkOf(1, 10), t0); len(pkts) != 1 {
		t.Fatal("trySend failed")
	}
	tx.onAck(1, 0, t0.Add(5*time.Millisecond))
	if tx.rto != 50 {
		t.Fatalf("rto floor: got %v, want 50 (5ms srtt -> 50 raw)", tx.rto)
	}
	// Retransmit fires exactly at the customized floor.
	if pkts := tx.trySend(chunkOf(2, 10), t0.Add(time.Second)); len(pkts) != 1 {
		t.Fatal("trySend failed")
	}
	if got := tx.pollRetransmit(t0.Add(time.Second + 49*time.Millisecond)); len(got) != 0 {
		t.Fatalf("retransmit fired before the 50ms floor")
	}
	if got := tx.pollRetransmit(t0.Add(time.Second + 50*time.Millisecond)); len(got) != 1 {
		t.Fatalf("retransmit did not fire at the 50ms floor")
	}
	// Backoff growth is capped at the customized rtoMax (1000), not 3000.
	for i := 2; i <= 14; i++ {
		tx.pollRetransmit(t0.Add(time.Duration(i*10) * time.Second))
	}
	if tx.rto != 1000 {
		t.Fatalf("rto ceiling: got %v, want 1000", tx.rto)
	}

	// Defaults unchanged: floor 250 on a fast sample, ceiling 3000.
	def := newOutChannel(testSeal)
	if pkts := def.trySend(chunkOf(1, 10), t0); len(pkts) != 1 {
		t.Fatal("trySend failed")
	}
	def.onAck(1, 0, t0.Add(5*time.Millisecond))
	if def.rto != 250 {
		t.Fatalf("default rto floor: got %v, want 250", def.rto)
	}
	if pkts := def.trySend(chunkOf(2, 10), t0.Add(time.Second)); len(pkts) != 1 {
		t.Fatal("trySend failed")
	}
	if got := def.pollRetransmit(t0.Add(time.Second + 249*time.Millisecond)); len(got) != 0 {
		t.Fatalf("default retransmit fired before 250ms")
	}
	if got := def.pollRetransmit(t0.Add(time.Second + 250*time.Millisecond)); len(got) != 1 {
		t.Fatalf("default retransmit did not fire at 250ms")
	}
	for i := 2; i <= 20; i++ {
		def.pollRetransmit(t0.Add(time.Duration(i*10) * time.Second))
	}
	if def.rto != 3000 {
		t.Fatalf("default rto ceiling: got %v, want 3000", def.rto)
	}
}

func TestInChannelBufferCapAxis(t *testing.T) {
	feed := func(in *InChannel, seq uint32) {
		body := make([]byte, 4, 4+8)
		binaryBigEndianPutUint32(body, seq)
		body = append(body, chunkOf(int(seq), 8)...)
		in.onDataBody(body)
	}
	rx := newInChannelCap(128)
	for seq := uint32(2); seq <= 129; seq++ {
		feed(rx, seq)
	}
	if len(rx.recv) != 128 {
		t.Fatalf("at-cap cache size = %d, want 128 (no drop yet)", len(rx.recv))
	}
	feed(rx, 130) // 129 > 128: hopeless-desync drop clears the cache
	if len(rx.recv) != 0 {
		t.Fatalf("buffer axis: cache not dropped past cap (len=%d)", len(rx.recv))
	}
	if rx.expected != 1 {
		t.Fatalf("expected seq moved: %d", rx.expected)
	}
	// Default cap unchanged: 200 out-of-order entries stay cached.
	def := newInChannel()
	for seq := uint32(2); seq <= 201; seq++ {
		feed(def, seq)
	}
	if len(def.recv) != 200 {
		t.Fatalf("default buffer cap: cache size = %d, want 200", len(def.recv))
	}
}

// newSimParams builds the fake-clock sim with per-endpoint engine params
// (the Rust peer would carry its own env-matched values; both Go roles are
// driven here so mismatch combinations are testable).
func newSimParams(t *testing.T, clientParams, serverParams RtcChannelParams) *sim {
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
		client: newClientWithEntropyParams(spub, fixtureServerAddr, time.Unix(0, 0), newCounterRand(0xA0, clientScalar), clientParams),
		server: newServerWithEntropyParams(spub, spriv, fixtureClientAddr, time.Unix(0, 0), newCounterRand(0xB4, serverScalar), serverParams),
	}
}

func isRTCPSenderReport(p []byte) bool {
	return len(p) >= 2 && p[0]&0xc0 == 0x80 && p[1] == 200
}

func TestRtcKeepaliveAxis(t *testing.T) {
	// D3: the keepalive packet SHAPE is unchanged; only the cadence moves.
	cp := RtcChannelParams{KeepaliveEvery: 2 * time.Second}
	s := newSimParams(t, cp, RtcChannelParams{})
	s.runUntilConnected(t, 200)
	base := s.now
	fired := false
	for s.now.Sub(base) < 3*time.Second {
		s.step(50)
		for _, p := range s.c2s {
			if isRTCPSenderReport(p) {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("keepalive axis: no RTCP SR within 2s cadence")
	}

	// Default cadence unchanged: nothing before 5s, an SR lands by 6s.
	d := newSimParams(t, RtcChannelParams{}, RtcChannelParams{})
	d.runUntilConnected(t, 200)
	base = d.now
	early := false
	for d.now.Sub(base) < 3*time.Second {
		d.step(50)
		for _, p := range d.c2s {
			if isRTCPSenderReport(p) {
				early = true
			}
		}
	}
	if early {
		t.Fatalf("default keepalive fired before 5s")
	}
	late := false
	for d.now.Sub(base) < 6*time.Second {
		d.step(50)
		for _, p := range d.c2s {
			if isRTCPSenderReport(p) {
				late = true
			}
		}
	}
	if !late {
		t.Fatalf("default keepalive never fired by 6s")
	}
}

// countClientDataPkts drives the sim until the server received one more frame
// and returns how many client data packets were emitted since the call
// (deterministic with the counter rand: pad draw is always 0).
func countClientDataPkts(t *testing.T, s *sim, payload []byte) int {
	t.Helper()
	mark := len(s.serverFrames)
	s.client.SendFrame(payload)
	count := 0
	for i := 0; i < 300 && len(s.serverFrames) == mark; i++ {
		s.step(20)
		for _, pkt := range s.c2s {
			if len(pkt) < RTPHeaderLen+NonceSize+16 || pkt[0]&0xc0 != 0x80 {
				continue
			}
			if ctr, _, ok := openMask(s.client.rtcCipher, pkt[RTPHeaderLen:]); ok &&
				ctr >= dataCounterBase && ctr < parityCounterBase {
				count++
			}
		}
	}
	if len(s.serverFrames) == mark {
		t.Fatalf("frame never delivered to the server")
	}
	return count
}

func TestRtcChunkAxis(t *testing.T) {
	// 5000-byte frame -> sealed 5034 with the deterministic zero pad
	// (counterRand draws pad 0). chunk 300 -> ceil(5034/300) = 17 packets;
	// default chunk -> ceil(5034/1150) = 5 packets. Both > 4.
	s := newSimParams(t, RtcChannelParams{Chunk: 300}, RtcChannelParams{})
	s.runUntilConnected(t, 200)
	if got := countClientDataPkts(t, s, chunkOf(7, 5000)); got != 17 {
		t.Fatalf("chunk axis: %d data packets, want 17", got)
	}
	if len(s.serverFrames) == 0 || !bytes.Equal(s.serverFrames[len(s.serverFrames)-1], chunkOf(7, 5000)) {
		t.Fatalf("chunk axis frame corrupted")
	}

	d := newSimParams(t, RtcChannelParams{}, RtcChannelParams{})
	d.runUntilConnected(t, 200)
	if got := countClientDataPkts(t, d, chunkOf(7, 5000)); got != 5 {
		t.Fatalf("default chunk: %d data packets, want 5", got)
	}
}

// TestRtcChunkWindowMismatchStillFrames is the F5 coupling proof: the receiver
// is length-agnostic, so MISMATCHED chunk/window values must still deliver
// frames byte-exact. Matched values are catalogue policy, not protocol —
// there is no must-fail negative test here by design.
func TestRtcChunkWindowMismatchStillFrames(t *testing.T) {
	cp := RtcChannelParams{Chunk: 600, Window: 16}
	sp := RtcChannelParams{} // server side on today's defaults (1150/128)
	s := newSimParams(t, cp, sp)
	s.runUntilConnected(t, 200)
	payload := chunkOf(9, 4096)
	s.client.SendFrame(payload)
	for i := 0; i < 300 && len(s.serverFrames) == 0; i++ {
		s.step(20)
	}
	if len(s.serverFrames) != 1 || !bytes.Equal(s.serverFrames[0], payload) {
		t.Fatalf("chunk mismatch broke client->server framing")
	}
	// Reverse direction: server chunks at 1150, client receives at 600.
	reply := chunkOf(11, 2048)
	s.server.SendFrame(reply)
	for i := 0; i < 300 && len(s.clientFrames) == 0; i++ {
		s.step(20)
	}
	found := false
	for _, f := range s.clientFrames {
		if bytes.Equal(f, reply) {
			found = true
		}
	}
	if !found {
		t.Fatalf("chunk mismatch broke server->client framing")
	}
}

func TestPadAxisPadTargetWith(t *testing.T) {
	zero := newCounterRand(0x11, [32]byte{}) // intn always 0
	if got := padTargetWith(100, zero, defaultPadConfig()); got != 0 {
		t.Fatalf("zero rand pad = %d, want 0", got)
	}
	mx := axisMaxRand{}
	// Bucketed region: slack capped at MaxPad.
	if got := padTargetWith(100, mx, defaultPadConfig()); got != MaxPad {
		t.Fatalf("bucketed pad cap = %d, want %d", got, MaxPad)
	}
	if got := padTargetWith(240, mx, defaultPadConfig()); got != MaxPad {
		t.Fatalf("bucketed pad cap (bucket 1024) = %d, want %d", got, MaxPad)
	}
	if got := padTargetWith(5000, mx, defaultPadConfig()); got != MaxPad {
		t.Fatalf("bucketed pad cap (bucket 16384) = %d, want %d", got, MaxPad)
	}
	// Big-frame region: draw bound = bigPad.
	if got := padTargetWith(70000, mx, defaultPadConfig()); got != 4096 {
		t.Fatalf("big-frame pad = %d, want 4096", got)
	}
	// Custom axis values.
	cfg := rtcPadConfig{buckets: []int{300}, maxPad: 16, bigPad: 32}
	if got := padTargetWith(100, mx, cfg); got != 16 {
		t.Fatalf("custom bucket pad = %d, want 16", got)
	}
	if got := padTargetWith(1000, mx, cfg); got != 32 {
		t.Fatalf("custom big-frame pad = %d, want 32", got)
	}
	// maxPad 0 => deterministic zero padding.
	cfg0 := rtcPadConfig{buckets: []int{300, 4096}, maxPad: 0, bigPad: 0}
	for _, n := range []int{0, 1, 100, 500, 8000} {
		if got := padTargetWith(n, mx, cfg0); got != 0 {
			t.Fatalf("maxPad 0: pad(%d) = %d, want 0", n, got)
		}
	}
}

func TestPadAxisWireCompat(t *testing.T) {
	// padLen travels in-frame: every pad configuration must decode through the
	// shared openCtr (the receiver is length-agnostic).
	var key [32]byte
	for i := range key {
		key[i] = byte(i*17 + 3)
	}
	aead := mustAEAD(key)
	payload := bytes.Repeat([]byte{0x5A}, 1234)
	cfgs := []rtcPadConfig{
		defaultPadConfig(),
		{buckets: []int{300}, maxPad: 16, bigPad: 32},
		{buckets: []int{512, 2048, 16384}, maxPad: 0, bigPad: 0},
		{buckets: []int{65536}, maxPad: 64, bigPad: 4096},
	}
	for i, cfg := range cfgs {
		for _, plain := range [][]byte{payload, []byte("tiny"), make([]byte, 70000)} {
			sealed := sealCtrPad(aead, 7, plain, osMaskRand{}, cfg)
			got, err := openCtr(aead, 7, sealed)
			if err != nil {
				t.Fatalf("cfg %d: openCtr failed: %v", i, err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("cfg %d: plaintext mismatch (len %d)", i, len(plain))
			}
		}
	}
}

func TestRtcPadAxisEngineRoundTrip(t *testing.T) {
	// Engine-level: client pads with custom buckets / zero cap, the server
	// keeps DEFAULT pad config — frames must still arrive byte-exact.
	cp := RtcChannelParams{PadBuckets: []int{512, 2048}, MaxPad: 0, BigFramePadMax: 0}
	s := newSimParams(t, cp, RtcChannelParams{})
	s.runUntilConnected(t, 200)
	payload := chunkOf(3, 1500)
	s.client.SendFrame(payload)
	for i := 0; i < 300 && len(s.serverFrames) == 0; i++ {
		s.step(20)
	}
	if len(s.serverFrames) != 1 || !bytes.Equal(s.serverFrames[0], payload) {
		t.Fatalf("pad axis: frame corrupted through default-pad receiver")
	}
}
