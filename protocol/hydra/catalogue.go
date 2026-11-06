package hydra

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Signed Hydra capability catalogue (verifier side).
//
// The catalogue is a JSON document signed with a detached Ed25519
// signature over the EXACT bytes. LoadAndVerifyCatalogue checks: signature,
// size limit (256 KiB), JSON shape, schema==1, seq>0, validity window,
// per-entry field checks, expiry (expires_at > now), sequence watermark
// (seq >= min_seq) and revocations (fail-closed: a revoked server/recipe id
// invalidates the whole document).
//
// Unknown JSON fields are tolerated (forward compatibility); a schema other
// than 1 is rejected (no downgrade). This mirrors the Rust loader in
// hydra-adaptive/hydra src/control/catalogue.rs exactly; the cross-language
// test vector seed is fixed in both test suites.

// MaxCatalogueBytes caps the total serialized catalogue size (256 KiB).
const MaxCatalogueBytes = 256 << 10

// Catalogue is the verified capability document.
type Catalogue struct {
	Schema      uint64            `json:"schema"`
	Seq         uint64            `json:"seq"`
	IssuedAt    uint64            `json:"issued_at"`
	ExpiresAt   uint64            `json:"expires_at"`
	Servers     []CatalogueServer `json:"servers"`
	Recipes     []CatalogueRecipe `json:"recipes"`
	Revocations []string          `json:"revocations"`
}

// CatalogueServer describes one hydra server and its endpoints.
type CatalogueServer struct {
	ID        string              `json:"id"`
	Pubkey    string              `json:"pubkey"` // base64 (std alphabet) of 32-byte static public key
	Endpoints []CatalogueEndpoint `json:"endpoints"`
}

// CatalogueEndpoint is one reachable transport endpoint of a server.
type CatalogueEndpoint struct {
	Transport string `json:"transport"` // "wss" | "rtc"
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	Path      string `json:"path"` // must start with '/'
	SNI       string `json:"sni,omitempty"`
}

// CatalogueRecipe selects a transport with parameters for a server.
type CatalogueRecipe struct {
	ID        string         `json:"id"`
	Server    string         `json:"server"`    // server id
	Transport string         `json:"transport"` // "wss" | "rtc"
	Params    map[string]any `json:"params"`    // short keys -> number/string
	Requires  map[string]any `json:"requires"`  // short keys -> number/string
}

// IsRevoked reports whether id appears in the revocation list.
func (c *Catalogue) IsRevoked(id string) bool {
	for _, r := range c.Revocations {
		if r == id {
			return true
		}
	}
	return false
}

// CatalogueErrorCode classifies catalogue verification failures.
type CatalogueErrorCode string

const (
	ErrCatalogueSigInvalid CatalogueErrorCode = "sig_invalid"
	ErrCatalogueExpired    CatalogueErrorCode = "expired"
	ErrCatalogueSeqTooLow  CatalogueErrorCode = "seq_too_low"
	ErrCatalogueMalformed  CatalogueErrorCode = "malformed"
	ErrCatalogueTooLarge   CatalogueErrorCode = "too_large"
	ErrCatalogueRevoked    CatalogueErrorCode = "revoked"
)

// CatalogueError is a catalogue verification failure.
type CatalogueError struct {
	Code  CatalogueErrorCode
	Field string // for ErrCatalogueMalformed
	ID    string // for ErrCatalogueRevoked
}

func (e *CatalogueError) Error() string {
	switch e.Code {
	case ErrCatalogueSigInvalid:
		return "catalogue signature invalid"
	case ErrCatalogueExpired:
		return "catalogue expired"
	case ErrCatalogueSeqTooLow:
		return "catalogue seq below watermark"
	case ErrCatalogueMalformed:
		return fmt.Sprintf("malformed catalogue: %s", e.Field)
	case ErrCatalogueTooLarge:
		return "catalogue exceeds size limit"
	case ErrCatalogueRevoked:
		return fmt.Sprintf("revoked id in catalogue: %s", e.ID)
	default:
		return fmt.Sprintf("catalogue error: %s", e.Code)
	}
}

func malformed(field string) *CatalogueError {
	return &CatalogueError{Code: ErrCatalogueMalformed, Field: field}
}

// LoadAndVerifyCatalogue verifies a signed catalogue and returns the parsed
// document. Order of checks: signature over the exact bytes, size limit,
// JSON parse, schema/seq/window, per-entry fields, expiry (expires_at >
// now), sequence watermark (seq >= min_seq), revocations.
func LoadAndVerifyCatalogue(payload []byte, sig []byte, rootPub ed25519.PublicKey, now, minSeq uint64) (*Catalogue, error) {
	// 1. detached Ed25519 over EXACT bytes
	if !ed25519.Verify(rootPub, payload, sig) {
		return nil, &CatalogueError{Code: ErrCatalogueSigInvalid}
	}

	// 2. size limit
	if len(payload) > MaxCatalogueBytes {
		return nil, &CatalogueError{Code: ErrCatalogueTooLarge}
	}

	// 3. parse; encoding/json ignores unknown fields by default
	var cat Catalogue
	if err := json.Unmarshal(payload, &cat); err != nil {
		return nil, malformed("json")
	}

	// 4. top-level shape
	if cat.Schema != 1 {
		return nil, malformed("schema")
	}
	if cat.Seq == 0 {
		return nil, malformed("seq")
	}
	if cat.IssuedAt > cat.ExpiresAt {
		return nil, malformed("window")
	}

	// 5. per-entry fields
	for i := range cat.Servers {
		raw, err := base64.StdEncoding.DecodeString(cat.Servers[i].Pubkey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, malformed("pubkey")
		}
	}
	for _, srv := range cat.Servers {
		for _, ep := range srv.Endpoints {
			switch ep.Transport {
			case "wss", "rtc":
			default:
				return nil, malformed("transport")
			}
			if ep.Host == "" {
				return nil, malformed("host")
			}
			if ep.Port == 0 {
				return nil, malformed("port")
			}
			if len(ep.Path) == 0 || ep.Path[0] != '/' {
				return nil, malformed("path")
			}
		}
	}
	for i := range cat.Recipes {
		switch cat.Recipes[i].Transport {
		case "wss", "rtc":
		default:
			return nil, malformed("transport")
		}
		if !scalarMap(cat.Recipes[i].Params) {
			return nil, malformed("params")
		}
		if !scalarMap(cat.Recipes[i].Requires) {
			return nil, malformed("requires")
		}
	}

	// 6. expiry
	if cat.ExpiresAt <= now {
		return nil, &CatalogueError{Code: ErrCatalogueExpired}
	}

	// 7. sequence watermark
	if cat.Seq < minSeq {
		return nil, &CatalogueError{Code: ErrCatalogueSeqTooLow}
	}

	// 8. revocations (fail-closed on the whole document)
	for i := range cat.Servers {
		if cat.IsRevoked(cat.Servers[i].ID) {
			return nil, &CatalogueError{Code: ErrCatalogueRevoked, ID: cat.Servers[i].ID}
		}
	}
	for i := range cat.Recipes {
		if cat.IsRevoked(cat.Recipes[i].ID) {
			return nil, &CatalogueError{Code: ErrCatalogueRevoked, ID: cat.Recipes[i].ID}
		}
	}

	return &cat, nil
}

// scalarMap reports whether every value in the map is a number or a string
// (the only value kinds the catalogue schema allows in params/requires).
func scalarMap(m map[string]any) bool {
	for _, v := range m {
		switch v.(type) {
		case string, float64:
		default:
			return false
		}
	}
	return true
}
