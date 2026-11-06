package hydra

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The fixed keypair below is the cross-language test vector: the Rust
// catalogue tests (hydra-adaptive/hydra src/control/catalogue_test.rs)
// embed the SAME seed hex and the fixture in testdata/ was signed with it
// by the Rust `catalogue-sign` bin. Do not change the seed without
// regenerating the fixture (see testdata regeneration note in the Rust
// test header).
const fixedSeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

// secondSeedHex is a different fixed key used for the wrong-key case.
const secondSeedHex = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

func seedToKey(t *testing.T, seedHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("bad seed hex: %v", err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func fixedPriv(t *testing.T) ed25519.PrivateKey { return seedToKey(t, fixedSeedHex) }
func fixedPub(t *testing.T) ed25519.PublicKey {
	return fixedPriv(t).Public().(ed25519.PublicKey)
}

func loadFixture(t *testing.T) (payload []byte, sig []byte) {
	t.Helper()
	payload, err := os.ReadFile("testdata/catalogue_signed.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sigHex, err := os.ReadFile("testdata/catalogue_signed.json.sig")
	if err != nil {
		t.Fatalf("read fixture sig: %v", err)
	}
	sig, err = hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil {
		t.Fatalf("decode sig hex: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig size %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return payload, sig
}

func signPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	return ed25519.Sign(fixedPriv(t), payload)
}

func errCode(t *testing.T, err error) *CatalogueError {
	t.Helper()
	var ce *CatalogueError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CatalogueError, got %T: %v", err, err)
	}
	return ce
}

// fixture times (must match testdata/catalogue_signed.json):
// issued_at=1735689600, expires_at=1893456000, seq=42.

func TestCatalogueValidPass(t *testing.T) {
	payload, sig := loadFixture(t)
	cat, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), 1800000000, 42)
	if err != nil {
		t.Fatalf("valid fixture must load: %v", err)
	}
	if cat.Schema != 1 || cat.Seq != 42 {
		t.Fatalf("schema/seq = %d/%d, want 1/42", cat.Schema, cat.Seq)
	}
	if len(cat.Servers) != 1 || cat.Servers[0].ID != "srv-main" {
		t.Fatalf("servers = %+v", cat.Servers)
	}
	if len(cat.Servers[0].Endpoints) != 2 ||
		cat.Servers[0].Endpoints[0].Transport != "wss" ||
		cat.Servers[0].Endpoints[0].Port != 443 ||
		cat.Servers[0].Endpoints[0].Path != "/hydra" ||
		cat.Servers[0].Endpoints[0].SNI != "hy.example.net" ||
		cat.Servers[0].Endpoints[1].Transport != "rtc" {
		t.Fatalf("endpoints = %+v", cat.Servers[0].Endpoints)
	}
	if len(cat.Recipes) != 1 || cat.Recipes[0].ID != "rec-fast" ||
		cat.Recipes[0].Server != "srv-main" || cat.Recipes[0].Transport != "wss" ||
		cat.Recipes[0].Params["mtu"].(float64) != 1200 ||
		cat.Recipes[0].Params["mode"].(string) != "fast" ||
		cat.Recipes[0].Requires["tier"].(string) != "ultra" {
		t.Fatalf("recipes = %+v", cat.Recipes)
	}
	if !cat.IsRevoked("rec-legacy") || cat.IsRevoked("rec-fast") || cat.IsRevoked("srv-main") {
		t.Fatal("revocation lookup failed")
	}
}

func TestCatalogueTamperedByte(t *testing.T) {
	payload, sig := loadFixture(t)
	tampered := append([]byte(nil), payload...)
	tampered[10] ^= 0x01
	_, err := LoadAndVerifyCatalogue(tampered, sig, fixedPub(t), 1800000000, 1)
	if errCode(t, err).Code != ErrCatalogueSigInvalid {
		t.Fatalf("tampered payload: got %v, want sig_invalid", err)
	}
}

func TestCatalogueWrongKey(t *testing.T) {
	payload, sig := loadFixture(t)
	other := seedToKey(t, secondSeedHex).Public().(ed25519.PublicKey)
	_, err := LoadAndVerifyCatalogue(payload, sig, other, 1800000000, 1)
	if errCode(t, err).Code != ErrCatalogueSigInvalid {
		t.Fatalf("wrong key: got %v, want sig_invalid", err)
	}
}

func TestCatalogueExpired(t *testing.T) {
	payload, sig := loadFixture(t)
	// expires_at == 1893456000; loader demands expires_at > now
	_, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), 1893456000, 1)
	if errCode(t, err).Code != ErrCatalogueExpired {
		t.Fatalf("expired: got %v, want expired", err)
	}
}

func TestCatalogueSeqBelowWatermark(t *testing.T) {
	payload, sig := loadFixture(t)
	_, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), 1800000000, 43)
	if errCode(t, err).Code != ErrCatalogueSeqTooLow {
		t.Fatalf("seq rollback: got %v, want seq_too_low", err)
	}
	// equal watermark passes
	if _, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), 1800000000, 42); err != nil {
		t.Fatalf("seq == min_seq must pass: %v", err)
	}
}

// mutateAndSign loads the fixture JSON as a generic map, applies mutate,
// re-marshals and re-signs with the fixed key (the Go test holds the
// private key, so structural variants need no extra Rust fixtures).
func mutateAndSign(t *testing.T, mutate func(m map[string]any)) []byte {
	t.Helper()
	payload, _ := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	mutate(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func TestCatalogueMalformed(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		field   string
	}{
		{
			"schema downgrade",
			mutateAndSign(t, func(m map[string]any) { m["schema"] = float64(2) }),
			"schema",
		},
		{
			"seq zero",
			mutateAndSign(t, func(m map[string]any) { m["seq"] = float64(0) }),
			"seq",
		},
		{
			"inverted window",
			mutateAndSign(t, func(m map[string]any) { m["issued_at"] = float64(1893456001) }),
			"window",
		},
		{
			"empty host",
			mutateAndSign(t, func(m map[string]any) {
				srv := m["servers"].([]any)[0].(map[string]any)
				srv["endpoints"].([]any)[0].(map[string]any)["host"] = ""
			}),
			"host",
		},
		{
			"port zero",
			mutateAndSign(t, func(m map[string]any) {
				srv := m["servers"].([]any)[0].(map[string]any)
				srv["endpoints"].([]any)[0].(map[string]any)["port"] = float64(0)
			}),
			"port",
		},
		{
			"path without slash",
			mutateAndSign(t, func(m map[string]any) {
				srv := m["servers"].([]any)[0].(map[string]any)
				srv["endpoints"].([]any)[0].(map[string]any)["path"] = "hydra"
			}),
			"path",
		},
		{
			"bad endpoint transport",
			mutateAndSign(t, func(m map[string]any) {
				srv := m["servers"].([]any)[0].(map[string]any)
				srv["endpoints"].([]any)[0].(map[string]any)["transport"] = "ws"
			}),
			"transport",
		},
		{
			"bad recipe transport",
			mutateAndSign(t, func(m map[string]any) {
				rec := m["recipes"].([]any)[0].(map[string]any)
				rec["transport"] = "quic"
			}),
			"transport",
		},
		{
			"pubkey not base64",
			mutateAndSign(t, func(m map[string]any) {
				srv := m["servers"].([]any)[0].(map[string]any)
				srv["pubkey"] = "not-base64!!"
			}),
			"pubkey",
		},
		{
			"pubkey wrong length",
			mutateAndSign(t, func(m map[string]any) {
				srv := m["servers"].([]any)[0].(map[string]any)
				srv["pubkey"] = "AAAAAAAAAAAAAAAAAAAAAA==" // 16 bytes
			}),
			"pubkey",
		},
		{
			"non-scalar params",
			mutateAndSign(t, func(m map[string]any) {
				rec := m["recipes"].([]any)[0].(map[string]any)
				rec["params"] = map[string]any{"flag": true}
			}),
			"params",
		},
		{
			"non-scalar requires",
			mutateAndSign(t, func(m map[string]any) {
				rec := m["recipes"].([]any)[0].(map[string]any)
				rec["requires"] = map[string]any{"nums": []any{1, 2}}
			}),
			"requires",
		},
		{
			"truncated json",
			[]byte(`{"schema":1,"seq":42,"issued_at":1`),
			"json",
		},
		{
			"missing required field",
			func() []byte {
				out, _ := json.Marshal(map[string]any{
					"schema": 1, "seq": 42, "issued_at": 1,
				})
				return signPayload(t, out)
			}(),
			"json",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig := signPayload(t, tc.payload)
			_, err := LoadAndVerifyCatalogue(tc.payload, sig, fixedPub(t), 1800000000, 1)
			ce := errCode(t, err)
			if ce.Code != ErrCatalogueMalformed || ce.Field != tc.field {
				t.Fatalf("got %+v, want malformed(%s)", ce, tc.field)
			}
		})
	}
}

func TestCatalogueUnknownFieldsTolerated(t *testing.T) {
	payload := mutateAndSign(t, func(m map[string]any) {
		m["future_field"] = map[string]any{"whatever": float64(1)}
	})
	sig := signPayload(t, payload)
	if _, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), 1800000000, 1); err != nil {
		t.Fatalf("unknown fields must be tolerated: %v", err)
	}
}

func TestCatalogueRevocationFailClosed(t *testing.T) {
	payload := mutateAndSign(t, func(m map[string]any) {
		m["revocations"] = []any{"rec-legacy", "srv-main"}
	})
	sig := signPayload(t, payload)
	_, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), 1800000000, 1)
	ce := errCode(t, err)
	if ce.Code != ErrCatalogueRevoked || ce.ID != "srv-main" {
		t.Fatalf("got %+v, want revoked(srv-main)", ce)
	}
}

func TestCatalogueTooLarge(t *testing.T) {
	payload := mutateAndSign(t, func(m map[string]any) {
		srv := m["servers"].([]any)[0].(map[string]any)
		big := make([]byte, MaxCatalogueBytes+1024)
		for i := range big {
			big[i] = 'x'
		}
		srv["endpoints"].([]any)[0].(map[string]any)["sni"] = string(big)
	})
	sig := signPayload(t, payload)
	_, err := LoadAndVerifyCatalogue(payload, sig, fixedPub(t), 1800000000, 1)
	if errCode(t, err).Code != ErrCatalogueTooLarge {
		t.Fatalf("oversize: got %v, want too_large", err)
	}
}
