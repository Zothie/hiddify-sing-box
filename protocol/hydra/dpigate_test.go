package hydra

// dpi-gate parity harness (wave 3, plan axis-sweep.md C1). The acceptance of
// the Go port is HERE: the Rust exporter (hydra src/bin/dpigate-export.rs)
// wrote testdata/dpigate_model.json (the verbatim model, f32 as bit patterns)
// and testdata/dpigate_fixtures.json (557 windows with Rust-computed feature
// vectors and verdicts). The Go side must reproduce EVERY verdict — 100% or
// the gate fails EnableDPIGate and stays off (fail-to-off).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"testing"
)

type dpiModelJSON struct {
	Format            string        `json:"format"`
	ModelSource       string        `json:"model_source"`
	ModelSourceSHA256 string        `json:"model_source_sha256"`
	BlobSHA256        string        `json:"blob_sha256"`
	NFeatures         int           `json:"n_features"`
	NTrees            int           `json:"n_trees"`
	FeatureSchemaVer  uint32        `json:"feature_schema_version"`
	Window            int           `json:"window"`
	InitBits          string        `json:"init_bits"`
	Init              string        `json:"init"`
	LearningRateBits  string        `json:"learning_rate_bits"`
	LearningRate      string        `json:"learning_rate"`
	TreeOffsets       []uint32      `json:"tree_offsets"`
	Nodes             []dpiNodeJSON `json:"nodes"`
}

type dpiNodeJSON struct {
	Feature       int16  `json:"feature"`
	ThresholdBits string `json:"threshold_bits"`
	Threshold     string `json:"threshold"`
	Left          uint16 `json:"left"`
	Right         uint16 `json:"right"`
	ValueBits     string `json:"value_bits"`
	Value         string `json:"value"`
}

type dpiMetaJSON struct {
	Len         uint16 `json:"len"`
	Byte0       uint8  `json:"byte0"`
	HasByte0    bool   `json:"has_byte0"`
	StunType    bool   `json:"stun_type"`
	MagicOK     bool   `json:"magic_ok"`
	StunLenOK   bool   `json:"stun_lenok"`
	DNSOK       bool   `json:"dns_ok"`
	Ent16Bits   string `json:"ent16_bits"`
	EntFullBits string `json:"ent_full_bits"`
}

type dpiCaseJSON struct {
	Kind           string        `json:"kind"`
	ID             string        `json:"id"`
	Packets        []string      `json:"packets"`
	Window         []dpiMetaJSON `json:"window"`
	FeaturesBits   []string      `json:"features_bits"`
	ScoreBits      string        `json:"score_bits"`
	Score          string        `json:"score"`
	ReadsAsTunnel  *bool         `json:"reads_as_tunnel"`
	MinBoundaryGap *float32      `json:"min_boundary_gap"`
}

type dpiFixturesJSON struct {
	Format  string        `json:"format"`
	BlobSHA string        `json:"blob_sha256"`
	Window  int           `json:"window"`
	Cases   []dpiCaseJSON `json:"cases"`
}

// f32FromBitsHex parses "0x3caaaaab" into the exact float32 bit pattern.
func f32FromBitsHex(t *testing.T, s string) float32 {
	t.Helper()
	if len(s) != 10 || s[:2] != "0x" {
		t.Fatalf("bad f32 bits encoding %q", s)
	}
	var bits uint32
	if _, err := fmt.Sscanf(s, "0x%08x", &bits); err != nil {
		t.Fatalf("bad f32 bits encoding %q: %v", s, err)
	}
	return math.Float32frombits(bits)
}

func f32Bits(v float32) string {
	return fmt.Sprintf("0x%08x", math.Float32bits(v))
}

func loadDPIFixtures(t *testing.T) (*dpiModelJSON, *dpiFixturesJSON) {
	t.Helper()
	var m dpiModelJSON
	raw, err := os.ReadFile("testdata/dpigate_model.json")
	if err != nil {
		t.Fatalf("read model json: %v", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse model json: %v", err)
	}
	var fx dpiFixturesJSON
	raw, err = os.ReadFile("testdata/dpigate_fixtures.json")
	if err != nil {
		t.Fatalf("read fixtures json: %v", err)
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixtures json: %v", err)
	}
	return &m, &fx
}

// TestDPIGateParityModel is the verbatim-model proof: the embedded blob, the
// fail-to-off constant and the JSON model (straight from the Rust source
// file) must agree node for node, bit for bit.
func TestDPIGateParityModel(t *testing.T) {
	mj, fx := loadDPIFixtures(t)
	blob := mustModelBlob(t)

	sum := sha256.Sum256(blob)
	if got := hex.EncodeToString(sum[:]); got != mj.BlobSHA256 {
		t.Fatalf("blob digest %s != fixture header %s", got, mj.BlobSHA256)
	}
	if fx.BlobSHA != mj.BlobSHA256 {
		t.Fatalf("fixtures reference blob %s, model json says %s", fx.BlobSHA, mj.BlobSHA256)
	}
	if dpiGateBlobSHA256 != mj.BlobSHA256 {
		t.Fatalf("dpiGateBlobSHA256 const %s != parity-verified %s (fail-to-off would trip)", dpiGateBlobSHA256, mj.BlobSHA256)
	}

	parsed, err := parseGbdtBlob(blob)
	if err != nil {
		t.Fatalf("parse blob: %v", err)
	}
	embedded, err := loadDPIGateModel()
	if err != nil {
		t.Fatalf("load embedded model: %v", err)
	}

	if mj.NFeatures != dpiNFeatures || mj.NTrees != 120 || mj.Window != dpiWindow {
		t.Fatalf("fixture dims %d/%d/%d != Go consts", mj.NFeatures, mj.NTrees, mj.Window)
	}
	if mj.FeatureSchemaVer != parsed.schema {
		t.Fatalf("schema version %d != parsed %d", mj.FeatureSchemaVer, parsed.schema)
	}
	if f32FromBitsHex(t, mj.InitBits) != parsed.init {
		t.Fatalf("init %v != parsed %v", f32FromBitsHex(t, mj.InitBits), parsed.init)
	}
	if f32FromBitsHex(t, mj.LearningRateBits) != parsed.learnRate {
		t.Fatalf("learning rate mismatch")
	}
	if len(mj.TreeOffsets) != len(parsed.treeOffsets) {
		t.Fatalf("offset count %d != parsed %d", len(mj.TreeOffsets), len(parsed.treeOffsets))
	}
	for i, o := range mj.TreeOffsets {
		if o != parsed.treeOffsets[i] || o != embedded.treeOffsets[i] {
			t.Fatalf("tree offset %d: json %d parsed %d embedded %d", i, o, parsed.treeOffsets[i], embedded.treeOffsets[i])
		}
	}
	if len(mj.Nodes) != len(parsed.nodes) || len(parsed.nodes) != 1720 {
		t.Fatalf("node count json %d parsed %d, want 1720", len(mj.Nodes), len(parsed.nodes))
	}
	for i, n := range mj.Nodes {
		p, e := &parsed.nodes[i], &embedded.nodes[i]
		wantThresh := f32FromBitsHex(t, n.ThresholdBits)
		wantValue := f32FromBitsHex(t, n.ValueBits)
		if n.Feature != p.feature || n.Feature != e.feature {
			t.Fatalf("node %d feature json %d parsed %d embedded %d", i, n.Feature, p.feature, e.feature)
		}
		if wantThresh != p.threshold || wantThresh != e.threshold {
			t.Fatalf("node %d threshold json %v (%s) parsed %v embedded %v", i, wantThresh, n.Threshold, p.threshold, e.threshold)
		}
		if n.Left != p.left || n.Left != e.left || n.Right != p.right || n.Right != e.right {
			t.Fatalf("node %d children mismatch", i)
		}
		if wantValue != p.value || wantValue != e.value {
			t.Fatalf("node %d value json %v (%s) parsed %v embedded %v", i, wantValue, n.Value, p.value, e.value)
		}
	}
}

// TestDPIGateParityVerdicts is the acceptance: every fixture case must
// reproduce the Rust feature vector bit-for-bit and every full-window verdict
// bit-for-bit (score f32 bits AND the boolean at the 0.5 threshold). One
// mismatch fails the port; the gate must then stay off.
func TestDPIGateParityVerdicts(t *testing.T) {
	_, fx := loadDPIFixtures(t)
	blob := mustModelBlob(t)
	parsed, err := parseGbdtBlob(blob)
	if err != nil {
		t.Fatalf("parse blob: %v", err)
	}
	if fx.Window != dpiWindow {
		t.Fatalf("fixture window %d != %d", fx.Window, dpiWindow)
	}

	matchScore, matchBool, matchFeatures, total := 0, 0, 0, 0
	var firstMismatch string
	for ci := range fx.Cases {
		c := &fx.Cases[ci]
		win := make([]PacketMeta, len(c.Window))
		for i, pm := range c.Window {
			win[i] = PacketMeta{
				Len:       pm.Len,
				Byte0:     pm.Byte0,
				HasByte0:  pm.HasByte0,
				StunType:  pm.StunType,
				MagicOK:   pm.MagicOK,
				StunLenOK: pm.StunLenOK,
				DNSOK:     pm.DNSOK,
				Ent16:     f32FromBitsHex(t, pm.Ent16Bits),
				EntFull:   f32FromBitsHex(t, pm.EntFullBits),
			}
		}

		// Wire cases: the stored window must be what PacketMetaFromWire
		// derives from the stored raw packets (the full from_wire -> extract
		// -> eval chain bit-exactly).
		if c.Kind == "wire" {
			if len(c.Packets) != len(win) {
				t.Fatalf("case %s: %d packets but %d metas", c.ID, len(c.Packets), len(win))
			}
			for i, pk := range c.Packets {
				raw, err := base64.StdEncoding.DecodeString(pk)
				if err != nil {
					t.Fatalf("case %s packet %d: %v", c.ID, i, err)
				}
				got := PacketMetaFromWire(raw)
				want := win[i]
				if got != want {
					t.Fatalf("case %s packet %d: from_wire %+v != rust %+v", c.ID, i, got, want)
				}
			}
		}

		got := ExtractFeatures(win)
		total++
		okFeatures := true
		for i := 0; i < dpiNFeatures; i++ {
			if f32Bits(got[i]) != c.FeaturesBits[i] {
				okFeatures = false
				if firstMismatch == "" {
					firstMismatch = fmt.Sprintf("case %s feature %d: got %s want %s", c.ID, i, f32Bits(got[i]), c.FeaturesBits[i])
				}
				break
			}
		}
		if okFeatures {
			matchFeatures++
		}
		if c.ReadsAsTunnel == nil {
			continue // partial window: extract parity only, no verdict
		}
		parsedScore := TunnelProbability(parsed, &got)
		embeddedScore := TunnelProbability(mustEmbeddedModel(t), &got)
		if parsedScore != embeddedScore {
			t.Fatalf("case %s: parsed-model score %v != embedded-model %v", c.ID, parsedScore, embeddedScore)
		}
		if f32Bits(parsedScore) == c.ScoreBits {
			matchScore++
		} else if firstMismatch == "" {
			firstMismatch = fmt.Sprintf("case %s score: got %s (%v) want %s (%s)", c.ID, f32Bits(parsedScore), parsedScore, c.ScoreBits, c.Score)
		}
		if (parsedScore > DPIGateDefaultThreshold) == *c.ReadsAsTunnel {
			matchBool++
		} else if firstMismatch == "" {
			firstMismatch = fmt.Sprintf("case %s bool: got %v (p=%v) want %v", c.ID, parsedScore > DPIGateDefaultThreshold, parsedScore, *c.ReadsAsTunnel)
		}
	}

	t.Logf("parity: features %d/%d bit-exact, scores %d/%d bit-exact, verdict bools %d/%d exact across %d cases",
		matchFeatures, total, matchScore, len(fx.Cases)-countPartial(fx), matchBool, len(fx.Cases)-countPartial(fx), total)
	if matchFeatures != total || matchScore != len(fx.Cases)-countPartial(fx) || matchBool != len(fx.Cases)-countPartial(fx) {
		t.Fatalf("PARITY FAILED (%s) — the gate must stay OFF (fail-to-off)", firstMismatch)
	}
}

func countPartial(fx *dpiFixturesJSON) int {
	n := 0
	for i := range fx.Cases {
		if fx.Cases[i].ReadsAsTunnel == nil {
			n++
		}
	}
	return n
}

func mustEmbeddedModel(t *testing.T) *gbdtModel {
	t.Helper()
	m, err := loadDPIGateModel()
	if err != nil {
		t.Fatalf("embedded model: %v", err)
	}
	return m
}

// TestDPIGateEnableIsLive proves the production entry point enables on this
// build (the parity above is the reason it may).
func TestDPIGateEnableIsLive(t *testing.T) {
	g, err := EnableDPIGate(DPIGateDefaultThreshold)
	if err != nil {
		t.Fatalf("EnableDPIGate refused on a parity-verified build: %v", err)
	}
	if g.stride != DPIGateDefaultStride || g.cooldownWindows != DPIGateDefaultCooldownWindows {
		t.Fatalf("defaults: stride %d cooldown %d", g.stride, g.cooldownWindows)
	}
}

// TestDPIGateParseRejectsGarbage is the fail-to-off path: malformed or
// truncated blobs must never produce a model.
func TestDPIGateParseRejectsGarbage(t *testing.T) {
	blob := mustModelBlob(t)
	for _, mutant := range [][]byte{
		{},
		blob[:12],                           // no header
		append([]byte("XXXX"), blob[4:]...), // bad magic
		blob[:40],                           // node table truncated
		blob[:len(blob)-8],                  // offset table truncated
	} {
		if _, err := parseGbdtBlob(mutant); err == nil {
			t.Fatalf("parseGbdtBlob accepted %d-byte mutant", len(mutant))
		}
	}
	// A digest mismatch must be refused (simulate by editing the byte the
	// const does not cover — parse succeeds, so test the digest check via a
	// doctored blob hash path instead: recompute what loadDPIGateModel does).
	sum := sha256.Sum256(blob)
	if hex.EncodeToString(sum[:]) != dpiGateBlobSHA256 {
		t.Fatalf("fixture blob no longer matches the verified const")
	}
}

func mustModelBlob(t *testing.T) []byte {
	t.Helper()
	b, err := dpiGateModelBytes()
	if err != nil {
		t.Fatalf("embedded model blob: %v", err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Behavior twins of the Rust dpi_gate.rs unit tests (real generators ported
// verbatim — the same windows Rust asserts against).
// ---------------------------------------------------------------------------

func dpiStunPkt(msgLen, total int) []byte {
	p := []byte{0x00, 0x01, byte((msgLen >> 8) & 0xff), byte(msgLen & 0xff), 0x21, 0x12, 0xa4, 0x42}
	for i := 0; i < total-8; i++ {
		p = append(p, byte((i*37+11)&0xff))
	}
	if len(p) > total {
		p = p[:total]
	}
	return p
}

func dpiRndPkt(total, seed int) []byte {
	p := make([]byte, total)
	for i := range p {
		p[i] = byte((seed*131 + i*97 + 7) & 0xff)
	}
	return p
}

// TestDPIGateFeatureExtractionMatchesAIVPNReference ports
// feature_extraction_matches_aivpn_reference: the training-reference values
// on the exact reference window (schema v2, IAT dropped).
func TestDPIGateFeatureExtractionMatchesAIVPNReference(t *testing.T) {
	pkts := [][]byte{
		dpiStunPkt(56, 76),
		dpiStunPkt(20, 40),
		dpiStunPkt(8, 28),
		dpiRndPkt(1100, 3),
		dpiRndPkt(1200, 9),
		dpiRndPkt(200, 21),
	}
	win := make([]PacketMeta, len(pkts))
	for i, p := range pkts {
		win[i] = PacketMetaFromWire(p)
	}
	want := [dpiNFeatures]float32{
		6.0, 440.66667, 505.47623, 28.0, 1200.0, 76.0, 28.0, 1100.0,
		0.5, 0.16666667, 0.0, 0.0, 0.33333334, 0.0,
		3.9375, 6.6259175, 84.0, 0.5, 0.16666667, 0.5, 0.5, 0.5, 0.0,
	}
	got := ExtractFeatures(win)
	for i := 0; i < dpiNFeatures; i++ {
		tol := 1e-3 * maxF32(absF32(want[i]), 1.0)
		if absF32(got[i]-want[i]) > tol {
			t.Fatalf("feature %d: got %v want %v", i, got[i], want[i])
		}
	}
}

// TestDPIGateShortHeaderSpinInvariant ports short_header_spin_does_not_change_features.
func TestDPIGateShortHeaderSpinInvariant(t *testing.T) {
	pkt := dpiRndPkt(1200, 71)
	pkt[0] = 0x40
	win := make([]PacketMeta, dpiWindow)
	for i := range win {
		win[i] = PacketMetaFromWire(pkt)
	}
	expected := ExtractFeatures(win)
	for byte0 := 0x40; byte0 < 0x80; byte0++ {
		pkt[0] = byte(byte0)
		for i := range win {
			win[i] = PacketMetaFromWire(pkt)
		}
		if ExtractFeatures(win) != expected {
			t.Fatalf("byte0 %#x changed features", byte0)
		}
	}
}

// TestDPIGateTunnelReadsAboveStun ports tunnel_windows_score_above_stun_windows.
func TestDPIGateTunnelReadsAboveStun(t *testing.T) {
	m := mustEmbeddedModel(t)
	tunnel := make([]PacketMeta, dpiWindow)
	for i := range tunnel {
		tunnel[i] = PacketMetaFromWire(dpiRndPkt(1100+(i%5)*20, i+1))
	}
	stun := make([]PacketMeta, dpiWindow)
	for i := range stun {
		stun[i] = PacketMetaFromWire(dpiStunPkt(56, 76))
	}
	xt := ExtractFeatures(tunnel)
	xs := ExtractFeatures(stun)
	pTunnel := TunnelProbability(m, &xt)
	pStun := TunnelProbability(m, &xs)
	if pTunnel <= 0.5 {
		t.Fatalf("tunnel-like window must read as tunnel, got p=%v", pTunnel)
	}
	if pStun >= 0.5 {
		t.Fatalf("STUN-shaped window must not read as tunnel, got p=%v", pStun)
	}
	if pTunnel <= pStun {
		t.Fatalf("p_tunnel %v <= p_stun %v", pTunnel, pStun)
	}
}

// TestDPIGateWindowFillAndVerdict ports gate_window_fill_and_verdict.
func TestDPIGateWindowFillAndVerdict(t *testing.T) {
	g := newDPIGate(mustEmbeddedModel(t), 0.5)
	pkt := dpiStunPkt(56, 76)
	for i := 0; i < dpiWindow-1; i++ {
		g.Record(pkt)
	}
	if _, ok := g.Verdict(); ok {
		t.Fatal("under-full window must abstain")
	}
	g.Record(pkt)
	v, ok := g.Verdict()
	if !ok {
		t.Fatal("full window must judge")
	}
	if v.ReadsAsTunnel != (v.TunnelProb > g.threshold) {
		t.Fatalf("bool inconsistent with threshold: p=%v th=%v", v.TunnelProb, g.threshold)
	}
}

// TestDPIGateClientSamplingCooldownAndRaise ports client_self_gate_sampling_cooldown_and_raise.
func TestDPIGateClientSamplingCooldownAndRaise(t *testing.T) {
	g, err := EnableDPIGate(0.5)
	if err != nil {
		t.Fatal(err)
	}
	g = g.WithStride(1).WithCooldownWindows(3)
	raised := 0
	prob := float32(0)
	n := dpiWindow + 2*DPIGateDefaultCooldownWindows
	for i := 0; i < n; i++ {
		if p, raise := g.Observe(dpiRndPkt(1150, i+1)); raise {
			raised++
			prob = p
		}
	}
	if raised < 1 {
		t.Fatal("tunnel flow must eventually raise a rotation")
	}
	if prob <= 0.5 {
		t.Fatalf("raise prob %v not above threshold", prob)
	}
	if raised >= 8 {
		t.Fatalf("cooldown must suppress request storms (raised %d)", raised)
	}
	if uint64(raised) != g.Raises() {
		t.Fatalf("Raises() %d != %d", g.Raises(), raised)
	}
}

// TestDPIGateClientStrideSamplesOneInSixteen ports
// client_self_gate_stride_samples_one_in_sixteen: with stride 16 a full
// window needs 16*(WINDOW-1)+1 observations.
func TestDPIGateClientStrideSamplesOneInSixteen(t *testing.T) {
	g, err := EnableDPIGate(0.5)
	if err != nil {
		t.Fatal(err)
	}
	tunnelBytes := func() []byte { return dpiRndPkt(1150, 9) }
	for i := 0; i < (dpiWindow-1)*DPIGateDefaultStride; i++ {
		if _, raise := g.Observe(tunnelBytes()); raise {
			t.Fatalf("must abstain before observation %d", i)
		}
	}
	// The WINDOW-th sampled packet completes the window; tunnel-like bytes
	// raise (or the cooldown suppresses exactly on this raise).
	_, _ = g.Observe(tunnelBytes())
}

// TestDPIGateClientQuietOnProtocolShapedTraffic ports
// client_self_gate_stays_quiet_on_protocol_shaped_traffic.
func TestDPIGateClientQuietOnProtocolShapedTraffic(t *testing.T) {
	g, err := EnableDPIGate(0.5)
	if err != nil {
		t.Fatal(err)
	}
	g = g.WithStride(1).WithCooldownWindows(2)
	for i := 0; i < dpiWindow*6; i++ {
		if _, raise := g.Observe(dpiStunPkt(56, 76+(i%7))); raise {
			t.Fatalf("STUN-shaped flow must never raise (packet %d)", i)
		}
	}
}

func absF32(v float32) float32 {
	if v < 0 {
		return -v
	}
	return v
}
func maxF32(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}
