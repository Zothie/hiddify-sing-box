// Package hydra implements the hydra outbound protocol: WS(TLS) fronting
// with X25519 -> blake3 KDF -> ChaCha20Poly1305 AEAD frames, bucketed
// padding and multiplexed TCP/UDP sessions. It is wire-compatible with the
// Rust hydra client/server (vpns/hydra) v0.9 and v0.12.
package hydra

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Magic is the protocol identifier ("HYDR1").
var Magic = [5]byte{'H', 'Y', 'D', 'R', '1'}

// Wire layout constants (proto.rs).
const (
	NonceSize = 12
	SaltSize  = 16
	IDSize    = 16
	// MaxPad is the per-bucket padding cap (proto.rs MAX_PAD).
	MaxPad = 64
	// KeySize/TagSize derive from the AEAD.
	// A sealed frame on the wire is [u32 ctLen][nonce 12][ct], i.e.
	// 4 + NonceSize + ctLen bytes in total.
	SealHeaderSize = 4 + NonceSize
	// MaxFrameLen caps ctLen we are willing to buffer from the peer. Legit
	// server frames top out around 70 KiB (64 KiB payload + padding +
	// overhead); 1 MiB leaves headroom without allowing multi-GB allocations.
	MaxFrameLen = 1 << 20
)

// defaultPadBuckets is the proto.rs bucket ladder used when a candidate
// carries no pad_buckets axis.
var defaultPadBuckets = [...]int{256, 1024, 4096, 16384, 65536}

// padBucketMin/Max and maxPadBucketCount bound the pad_buckets axis
// (TUNING.md A5, audit F10): every bucket must lie in [256,65536], the
// ladder must be strictly ascending and at most 8 entries, so one hostile
// catalogue entry cannot turn the padding into an amplification vector.
const (
	padBucketMin      = 256
	padBucketMax      = 65536
	maxPadBucketCount = 8
	// bigPadDefault bounds the extra padding of frames above every bucket
	// (proto.rs rand 0..=4096); the axis can only lower it.
	bigPadDefault = 4096
)

// padConfig is the candidate-tuned frame-padding configuration shared by the
// ws path (padTargetFor/sealCtrFor) and the rtc path (rtc's
// padTargetWithConfig, which consumes it verbatim). The zero value / nil
// pointer reproduces proto.rs behavior byte-identically.
type padConfig struct {
	// buckets is the ascending bucket ladder; nil = defaultPadBuckets.
	buckets []int
	// maxPad caps the random per-bucket slack; 0 = MaxPad (64).
	maxPad int
	// bigPadMax bounds the extra padding above every bucket; 0 = 4096.
	bigPadMax int
}

// validatePadBuckets fail-closes a pad_buckets axis value: every entry must
// be an integer in [256,65536], strictly ascending, at most 8 entries.
func validatePadBuckets(buckets []uint32) error {
	if len(buckets) > maxPadBucketCount {
		return E.New("hydra: pad_buckets allows at most ", maxPadBucketCount, " entries, got ", len(buckets))
	}
	prev := 0
	for i, b := range buckets {
		if b < padBucketMin || b > padBucketMax {
			return E.New("hydra: pad_buckets entry ", i, " out of range ", padBucketMin, "..", padBucketMax, ": ", b)
		}
		if int(b) <= prev {
			return E.New("hydra: pad_buckets must be strictly ascending, entry ", i, "=", b)
		}
		prev = int(b)
	}
	return nil
}

// newPadConfig builds the padding configuration from a validated pad_buckets
// axis (nil = default ladder) and the max_pad / big_pad_max axes (0 =
// defaults 64 / 4096).
func newPadConfig(buckets []uint32, maxPadAxis, bigPadMaxAxis uint32) *padConfig {
	cfg := &padConfig{maxPad: MaxPad, bigPadMax: bigPadDefault}
	if maxPadAxis > 0 {
		cfg.maxPad = min(int(maxPadAxis), MaxPad)
	}
	if bigPadMaxAxis > 0 {
		cfg.bigPadMax = min(int(bigPadMaxAxis), bigPadDefault)
	}
	if len(buckets) > 0 {
		cfg.buckets = make([]int, len(buckets))
		for i, b := range buckets {
			cfg.buckets[i] = int(b)
		}
	}
	return cfg
}

// padTargetFor mirrors proto.rs pad_target under cfg: round the plaintext up
// to the next size bucket and add 0..=min(slack, cfg.maxPad) random pad
// bytes (0..=cfg.bigPadMax for frames exceeding every bucket). A nil cfg is
// the proto.rs default configuration.
func (c *padConfig) padTargetFor(plainLen int) int {
	maxPad, bigPad := MaxPad, bigPadDefault
	buckets := defaultPadBuckets[:]
	if c != nil {
		if c.maxPad > 0 {
			maxPad = c.maxPad
		}
		if c.bigPadMax > 0 {
			bigPad = c.bigPadMax
		}
		if len(c.buckets) > 0 {
			buckets = c.buckets
		}
	}
	need := plainLen + 3 + 16
	for _, b := range buckets {
		if need <= b {
			slack := b - need
			if slack > maxPad {
				slack = maxPad
			}
			return randRangeInclusive(slack)
		}
	}
	return randRangeInclusive(bigPad)
}

// padTarget mirrors proto.rs pad_target: round the plaintext up to the next
// size bucket and add 0..=min(slack, 64) random pad bytes (0..=4096 for
// frames exceeding every bucket). Only the [pad_len u16][pad][payload] parse
// format matters for interop; the exact pad length is intentionally random.
func padTarget(plainLen int) int {
	return (*padConfig)(nil).padTargetFor(plainLen)
}

// randRangeInclusive returns a uniform int in [0, n] (Rust gen_range(0..=n));
// n <= 0 yields 0.
func randRangeInclusive(n int) int {
	if n <= 0 {
		return 0
	}
	// Rejection-free uniform draw over n+1 values from a 64-bit pool:
	// lim = largest multiple of (n+1) that fits in uint64.
	lim := (^uint64(0) / uint64(n+1)) * uint64(n+1)
	var v uint64
	b := make([]byte, 8)
	for {
		if _, err := rand.Read(b); err != nil {
			return 0
		}
		v = binary.BigEndian.Uint64(b)
		if v < lim {
			return int(v % uint64(n+1))
		}
	}
}

// deriveKey computes blake3::derive_key(context, material).
func deriveKey(context string, material []byte) []byte {
	key := make([]byte, chacha20poly1305.KeySize)
	blake3.DeriveKey(context, material, key)
	return key
}

func aeadFromKey(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// kdfHello mirrors proto.rs kdf_hello.
func kdfHello(serverStatic, salt []byte) (cipher.AEAD, error) {
	material := make([]byte, 0, len(serverStatic)+len(salt))
	material = append(material, serverStatic...)
	material = append(material, salt...)
	return aeadFromKey(deriveKey("hydra-hello", material))
}

// kdfAuth mirrors proto.rs kdf_auth:
// derive_key("hydra-v1", shared_eph || shared_static || salt || transcript).
func kdfAuth(sharedEph, sharedStatic, salt, transcript []byte) (cipher.AEAD, error) {
	material := make([]byte, 0, len(sharedEph)+len(sharedStatic)+len(salt)+len(transcript))
	material = append(material, sharedEph...)
	material = append(material, sharedStatic...)
	material = append(material, salt...)
	material = append(material, transcript...)
	return aeadFromKey(deriveKey("hydra-v1", material))
}

// aadFor mirrors proto.rs aad_for: MAGIC || counter u64 BE.
func aadFor(counter uint64) []byte {
	aad := make([]byte, 0, len(Magic)+8)
	aad = append(aad, Magic[:]...)
	return binary.BigEndian.AppendUint64(aad, counter)
}

// sealCtr mirrors proto.rs seal_ctr under the DEFAULT padding configuration:
// [u32 ctLen][nonce(4 random || counter BE)][ct]; plaintext becomes
// [padLen u16 BE][pad][payload].
func sealCtr(aead cipher.AEAD, counter uint64, plaintext []byte) []byte {
	return sealCtrFor(aead, counter, plaintext, nil)
}

// sealCtrFor is sealCtr with the candidate's padding configuration; a nil
// cfg is byte-identical to sealCtr.
func sealCtrFor(aead cipher.AEAD, counter uint64, plaintext []byte, cfg *padConfig) []byte {
	nonce := make([]byte, NonceSize)
	// crypto/rand never fails on Linux short reads; a failure here leaves the
	// zero prefix which still yields a valid (if weaker) frame.
	_, _ = rand.Read(nonce[:4])
	binary.BigEndian.PutUint64(nonce[4:], counter)

	padLen := cfg.padTargetFor(len(plaintext))
	inner := make([]byte, 2+padLen+len(plaintext))
	binary.BigEndian.PutUint16(inner, uint16(padLen))
	if padLen > 0 {
		_, _ = rand.Read(inner[2 : 2+padLen])
	}
	copy(inner[2+padLen:], plaintext)

	ct := aead.Seal(nil, nonce, inner, aadFor(counter))
	out := make([]byte, 0, SealHeaderSize+len(ct))
	out = binary.BigEndian.AppendUint32(out, uint32(len(ct)))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}

// ErrBadFrame is returned for any malformed or unauthenticated frame.
var ErrBadFrame = errors.New("hydra: bad frame")

// openCtr mirrors proto.rs open_ctr: parses [u32 ctLen][nonce 12][ct],
// decrypts with AAD = MAGIC||counter and strips [padLen u16][pad].
func openCtr(aead cipher.AEAD, counter uint64, frame []byte) ([]byte, error) {
	if len(frame) < SealHeaderSize+1 {
		return nil, ErrBadFrame
	}
	ctLen := binary.BigEndian.Uint32(frame[:4])
	if uint64(ctLen) < NonceSize || uint64(len(frame)-SealHeaderSize) < uint64(ctLen) {
		return nil, ErrBadFrame
	}
	nonce := frame[4:16]
	ct := frame[16 : 16+ctLen]
	inner, err := aead.Open(nil, nonce, ct, aadFor(counter))
	if err != nil {
		return nil, ErrBadFrame
	}
	if len(inner) < 2 {
		return nil, ErrBadFrame
	}
	padLen := int(binary.BigEndian.Uint16(inner))
	if len(inner) < 2+padLen {
		return nil, ErrBadFrame
	}
	return inner[2+padLen:], nil
}

// frameStream is the incremental decoder for the wire byte stream of
// concatenated sealed frames with per-frame counters (proto.rs FrameStream).
// It is NOT safe for concurrent use; a single tunnel reader goroutine owns it.
type frameStream struct {
	aead cipher.AEAD
	ctr  uint64
	buf  []byte
	bad  bool
}

func newFrameStream(aead cipher.AEAD, startCtr uint64) *frameStream {
	return &frameStream{aead: aead, ctr: startCtr}
}

// feed appends wire bytes and returns newly decrypted, non-empty plaintext
// frames in order. After a crypto failure (bad latch) all further input is
// rejected — fail closed, same as the Rust reader.
func (fs *frameStream) feed(b []byte) ([][]byte, error) {
	if fs.bad || len(b) == 0 {
		return nil, nil
	}
	fs.buf = append(fs.buf, b...)
	var out [][]byte
	for {
		if len(fs.buf) < 4 {
			break
		}
		l := binary.BigEndian.Uint32(fs.buf)
		if l > MaxFrameLen {
			fs.bad = true
			return nil, ErrBadFrame
		}
		if uint64(len(fs.buf)) < 16+uint64(l) {
			break
		}
		plain, err := openCtr(fs.aead, fs.ctr, fs.buf[:16+l])
		if err != nil {
			fs.bad = true
			return nil, err
		}
		// Empty plaintexts are dropped but still advance the counter
		// (matches proto.rs FrameStream::feed).
		fs.ctr++
		fs.buf = fs.buf[16+l:]
		if len(plain) > 0 {
			out = append(out, plain)
		}
	}
	return out, nil
}

// consumed returns the next expected counter (proto.rs FrameStream::consumed).
func (fs *frameStream) consumed() uint64 { return fs.ctr }

// x25519Pub computes the public key for a scalar (clamping per RFC 7748,
// same as x25519-dalek).
func x25519Pub(sk []byte) ([]byte, error) {
	return curve25519.X25519(sk, curve25519.Basepoint)
}

// x25519 computes the raw DH shared secret.
func x25519(sk, pk []byte) ([]byte, error) {
	return curve25519.X25519(sk, pk)
}

// decodeB64 decodes standard-alphabet base64, tolerating missing padding
// (the Rust b64decode strips '=' leniently).
func decodeB64(s string) ([]byte, error) {
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// constantTimeEquals is used for CONFIRM comparison.
func constantTimeEquals(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
