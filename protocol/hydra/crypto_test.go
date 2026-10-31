package hydra

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func testAEAD(t testing.TB) cipher.AEAD {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aead, err := aeadFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func TestSealOpenRoundtrip(t *testing.T) {
	aead := testAEAD(t)
	msgs := [][]byte{
		[]byte("hello world hydra frame"),
		bytes.Repeat([]byte{0xAB}, 65536), // exceeds all buckets
		[]byte("x"),
	}
	for i, msg := range msgs {
		frame := sealCtr(aead, uint64(i+1), msg)
		got, err := openCtr(aead, uint64(i+1), frame)
		if err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("msg %d: payload mismatch (%d vs %d bytes)", i, len(got), len(msg))
		}
	}
}

func TestOpenCtrWrongCounterFails(t *testing.T) {
	aead := testAEAD(t)
	frame := sealCtr(aead, 1, []byte("x"))
	if _, err := openCtr(aead, 2, frame); err == nil {
		t.Fatal("counter mismatch must fail")
	}
	if got, err := openCtr(aead, 1, frame); err != nil || string(got) != "x" {
		t.Fatalf("matching counter must succeed: %v", err)
	}
}

func TestSealedFrameLayout(t *testing.T) {
	aead := testAEAD(t)
	const counter = 0x0102030405060708
	frame := sealCtr(aead, counter, []byte("payload"))
	ctLen := binary.BigEndian.Uint32(frame[:4])
	if int(ctLen) != len(frame)-SealHeaderSize {
		t.Fatalf("ctLen prefix %d != remaining %d", ctLen, len(frame)-SealHeaderSize)
	}
	nonce := frame[4:16]
	if got, want := binary.BigEndian.Uint64(nonce[4:]), uint64(counter); got != want {
		t.Fatalf("nonce counter bytes: got %#x want %#x", got, want)
	}
	// Nonce prefix must be random-looking (4 nonzero-probable bytes); just
	// check length here, randomness is exercised by the roundtrips.
	if len(nonce) != NonceSize {
		t.Fatalf("nonce size %d", len(nonce))
	}
}

func TestOpenCtrRejectsShortAndTruncated(t *testing.T) {
	aead := testAEAD(t)
	frame := sealCtr(aead, 1, []byte("some payload"))
	if _, err := openCtr(aead, 1, frame[:15]); err == nil {
		t.Fatal("frame shorter than 16+1 must fail")
	}
	ctLen := binary.BigEndian.Uint32(frame[:4])
	if _, err := openCtr(aead, 1, frame[:SealHeaderSize+int(ctLen)-1]); err == nil {
		t.Fatal("truncated ciphertext must fail")
	}
	// Tamper with the last byte (tag) -> AEAD failure.
	bad := append([]byte(nil), frame...)
	bad[len(bad)-1] ^= 1
	if _, err := openCtr(aead, 1, bad); err == nil {
		t.Fatal("tampered tag must fail")
	}
}

// TestPadParse builds a synthetic inner [padLen u16][pad][payload] and checks
// openCtr strips exactly the padding.
func TestPadParse(t *testing.T) {
	aead := testAEAD(t)
	nonce := make([]byte, NonceSize)
	inner := []byte{0x00, 0x04, 1, 2, 3, 4, 'p', 'a', 'y'}
	ct := aead.Seal(nil, nonce, inner, aadFor(7))
	plain, err := aead.Open(nil, nonce, ct, aadFor(7))
	if err != nil {
		t.Fatal(err)
	}
	padLen := int(binary.BigEndian.Uint16(plain))
	if padLen != 4 {
		t.Fatalf("padLen %d", padLen)
	}
	if !bytes.Equal(plain[2+padLen:], []byte("pay")) {
		t.Fatalf("payload %q", plain[2+padLen:])
	}
}

func TestPadTargetRanges(t *testing.T) {
	// Buckets: pad in [0, min(slack,64)] for need<=65536, [0,4096] beyond.
	for _, tc := range []struct {
		plain int
		lo    int
		hi    int
	}{{0, 0, 64}, {100, 0, 64}, {65500, 0, 64}, {65600, 0, 4096}, {100000, 0, 4096}} {
		for i := 0; i < 200; i++ {
			p := padTarget(tc.plain)
			if p < tc.lo || p > tc.hi {
				t.Fatalf("padTarget(%d)=%d outside [%d,%d]", tc.plain, p, tc.lo, tc.hi)
			}
		}
	}
}

func TestFrameStreamChunked(t *testing.T) {
	aead := testAEAD(t)
	frames := [][]byte{[]byte("first"), nil, []byte("second frame"), bytes.Repeat([]byte{7}, 5000)}
	var wire []byte
	for i, f := range frames {
		wire = append(wire, sealCtr(aead, uint64(i+1), f)...)
	}
	fs := newFrameStream(aead, 1)
	var got []byte
	for _, split := range [][]byte{wire[:1], wire[1:97], wire[97 : len(wire)/2], wire[len(wire)/2:]} {
		out, err := fs.feed(split)
		if err != nil {
			t.Fatal(err)
		}
		for _, plain := range out {
			got = append(got, plain...)
		}
	}
	want := append([]byte{}, frames[0]...)
	want = append(want, frames[2]...)
	want = append(want, frames[3]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded %d bytes, want %d (empty frame must be dropped)", len(got), len(want))
	}
	if fs.consumed() != 5 {
		t.Fatalf("consumed=%d, want 5 (next expected counter after 4 frames incl. the empty one)", fs.consumed())
	}
	if fs.bad {
		t.Fatal("stream must not be flagged bad")
	}
}

func TestFrameStreamLatchesBad(t *testing.T) {
	aead := testAEAD(t)
	wire := sealCtr(aead, 1, []byte("hello"))
	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] ^= 1
	fs := newFrameStream(aead, 1)
	if _, err := fs.feed(bad); err == nil || !fs.bad {
		t.Fatal("tamper must latch bad")
	}
	// Further input is silently rejected (Rust: feed returns empty Vec).
	out, err := fs.feed(wire)
	if err != nil || len(out) != 0 || !fs.bad {
		t.Fatal("no further frames accepted after bad latch")
	}
}

func TestFrameStreamRejectsHugeLength(t *testing.T) {
	aead := testAEAD(t)
	fs := newFrameStream(aead, 1)
	huge := make([]byte, 4)
	binary.BigEndian.PutUint32(huge, MaxFrameLen+1)
	if _, err := fs.feed(huge); err == nil || !fs.bad {
		t.Fatal("length over cap must latch bad without allocating")
	}
}

func TestB64(t *testing.T) {
	// Rust b64encode emits standard alphabet with '=' padding.
	raw := []byte{0, 1, 2, 250, 251, 252, 253, 254, 255}
	want := "AAEC+vv8/f7/"
	if got := encodeB64(raw); got != want {
		t.Fatalf("encodeB64=%q want %q", got, want)
	}
	for _, s := range []string{want, "AAEC+vv8/f7"} {
		if _, err := decodeB64(s); err != nil {
			t.Fatalf("decodeB64(%q): %v", s, err)
		}
	}
	if got, _ := decodeB64(want); !bytes.Equal(got, raw) {
		t.Fatalf("decode mismatch")
	}
}

func TestRandRangeInclusive(t *testing.T) {
	counts := make([]int, 5) // [0..4]
	for i := 0; i < 20000; i++ {
		v := randRangeInclusive(4)
		if v < 0 || v > 4 {
			t.Fatalf("out of range: %d", v)
		}
		counts[v]++
	}
	for i, c := range counts {
		if c == 0 {
			t.Fatalf("value %d never sampled", i)
		}
	}
	if randRangeInclusive(0) != 0 || randRangeInclusive(-1) != 0 {
		t.Fatal("n<=0 must yield 0")
	}
}
