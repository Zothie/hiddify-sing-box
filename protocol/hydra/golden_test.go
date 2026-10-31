package hydra

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

// Golden vectors exported from the Rust reference implementation
// (vpns/hydra tests/export_vectors.rs, `cargo test --release export_vectors
// -- --ignored --nocapture`). Fixed inputs:
//
//	server_static = 0102..20  eph_sk = i*3+7  salt = 0xA0..AF
//	shared_eph = i^0x5A  shared_static = i^0xA5  transcript = eph_pub||eph_pub
//
// The Go side must derive identical KDF keys AND decrypt the Rust-sealed
// frames. (Sealed frames cannot be re-sealed deterministically: the nonce
// carries 4 random bytes — so the vectors are cross-checked by decryption.)
const (
	goldenServerStatic = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	goldenSalt         = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	goldenEphPub       = "5dcf0d8a6a6141364cb5fd97e47c753e6f3fc72acc1550ed38a51cd9274a8d37"
	goldenKdfHelloKey  = "37db2729312107fdf07bceef415d70729ac3d0ccd56d72ce5421e884028fd16e"
	goldenHelloPlain   = "48594452315dcf0d8a6a6141364cb5fd97e47c753e6f3fc72acc1550ed38a51cd9274a8d37"
	goldenHelloFrame   = "0000005a311026de0000000000000000084c5be43dbdca33143bf333fff0ad51a098656177e8936681c3c754cd01800b3d08fc27f70f97dae1c0173bd432bf9e56862d55d6465c3539613a35d7ef47f2f71f73c09a99b0e8e1372b5c90439b2c19c39e4883758d6323d1"
	goldenKdfAuthKey   = "4883fea53bb0a52b30b9a56cd2f28b7220a4790d0a06edcb99181604ab8aa217"
	goldenAad0         = "48594452310000000000000000"
	goldenAad1         = "48594452310000000000000001"
	goldenAad65535     = "4859445231000000000000ffff"
	goldenConfirmFrame = "0000004aec11069d00000000000000011e7979d14ee0fecf8fcea48f479e28cc97c0d78af0259ec8149db82e63f8814f28813380fbdd391cb04315de38f576a519edceb2c51614a3d4170a606802ba01fd43faeb00405cf0717f"
	goldenStream       = "00000046f1fa12ef0000000000000001fbeb26f703bd702b001b6d945e95a149d47d65b99ccb1e0fd57b53f9cd62028ebef466e3faed593dbcae345e1794548f2a9c3eb9b80a74432c6cdee467fd23ca3f008e4004f70000002848d583a800000000000000022c9c5acd74fbc346a7fe7c0b734bc5f210df6ef2ad83b117a9d64745adccd10a186383ecd85af8720000002c34c804ed0000000000000003be32aabe28f1fc06039dc98a04b2ebe6fbfc0c1d94bca127f6a57a2d7008a58f53b9f4c44b2cdf3cb0bfd7ce"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goldenKDFs(t *testing.T) (serverStatic, salt []byte, helloAEAD, authAEAD cipher.AEAD) {
	t.Helper()
	serverStatic = mustHex(t, goldenServerStatic)
	salt = mustHex(t, goldenSalt)
	helloAEAD, err := kdfHello(serverStatic, salt)
	if err != nil {
		t.Fatal(err)
	}
	sharedEph := make([]byte, 32)
	sharedStatic := make([]byte, 32)
	for i := 0; i < 32; i++ {
		sharedEph[i] = byte(i) ^ 0x5A
		sharedStatic[i] = byte(i) ^ 0xA5
	}
	ephPub := mustHex(t, goldenEphPub)
	transcript := append(append([]byte{}, ephPub...), ephPub...)
	authAEAD, err = kdfAuth(sharedEph, sharedStatic, salt, transcript)
	if err != nil {
		t.Fatal(err)
	}
	return serverStatic, salt, helloAEAD, authAEAD
}

func TestGoldenKDFKeys(t *testing.T) {
	serverStatic := mustHex(t, goldenServerStatic)
	salt := mustHex(t, goldenSalt)
	helloMaterial := append(append([]byte{}, serverStatic...), salt...)
	if got := hex.EncodeToString(deriveKey("hydra-hello", helloMaterial)); got != goldenKdfHelloKey {
		t.Fatalf("kdf_hello key mismatch:\n got %s\nwant %s", got, goldenKdfHelloKey)
	}
	sharedEph := make([]byte, 32)
	sharedStatic := make([]byte, 32)
	for i := 0; i < 32; i++ {
		sharedEph[i] = byte(i) ^ 0x5A
		sharedStatic[i] = byte(i) ^ 0xA5
	}
	ephPub := mustHex(t, goldenEphPub)
	material := append(append(append(append([]byte{}, sharedEph...), sharedStatic...), salt...), ephPub...)
	material = append(material, ephPub...)
	if got := hex.EncodeToString(deriveKey("hydra-v1", material)); got != goldenKdfAuthKey {
		t.Fatalf("kdf_auth key mismatch:\n got %s\nwant %s", got, goldenKdfAuthKey)
	}
}

func TestGoldenAAD(t *testing.T) {
	if got := hex.EncodeToString(aadFor(0)); got != goldenAad0 {
		t.Fatalf("aad0=%s", got)
	}
	if got := hex.EncodeToString(aadFor(1)); got != goldenAad1 {
		t.Fatalf("aad1=%s", got)
	}
	if got := hex.EncodeToString(aadFor(65535)); got != goldenAad65535 {
		t.Fatalf("aad65535=%s", got)
	}
}

// TestGoldenHello decrypts the Rust-sealed hello frame under kdf_hello at
// counter 0 and requires MAGIC||eph_pub.
func TestGoldenHello(t *testing.T) {
	_, _, helloAEAD, _ := goldenKDFs(t)
	plain, err := openCtr(helloAEAD, 0, mustHex(t, goldenHelloFrame))
	if err != nil {
		t.Fatalf("decrypt Rust hello: %v", err)
	}
	if got, want := hex.EncodeToString(plain), goldenHelloPlain; got != want {
		t.Fatalf("hello plaintext mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestGoldenConfirm decrypts the Rust CONFIRM frame (counter 1).
func TestGoldenConfirm(t *testing.T) {
	_, _, _, authAEAD := goldenKDFs(t)
	plain, err := openCtr(authAEAD, 1, mustHex(t, goldenConfirmFrame))
	if err != nil {
		t.Fatalf("decrypt Rust confirm: %v", err)
	}
	if !bytes.Equal(plain, []byte("hydra-confirm")) {
		t.Fatalf("confirm plaintext %q", plain)
	}
}

// TestGoldenStream feeds the Rust-sealed 3-frame stream (counters 1..3, third
// frame empty) through the Go FrameStream decoder.
func TestGoldenStream(t *testing.T) {
	_, _, _, authAEAD := goldenKDFs(t)
	fs := newFrameStream(authAEAD, 1)
	frames, err := fs.feed(mustHex(t, goldenStream))
	if err != nil {
		t.Fatalf("decode Rust stream: %v", err)
	}
	if len(frames) != 2 ||
		string(frames[0]) != "alpha" || string(frames[1]) != "beta" {
		t.Fatalf("stream frames %q (empty Rust frame must be dropped)", frames)
	}
	if fs.consumed() != 4 {
		t.Fatalf("consumed=%d, want 4 (empty frame advances the counter)", fs.consumed())
	}
}
