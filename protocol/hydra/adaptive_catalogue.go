package hydra

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"

	"github.com/sagernet/sing-box/option"
)

// Catalogue -> adaptive outbound candidate expansion.
//
// CandidatesFromCatalogue turns a VERIFIED catalogue (see
// LoadAndVerifyCatalogue) into option.HydraAdaptiveCandidateOptions entries
// for the hydra adaptive outbound. Only the wss transport is wired today:
// rtc endpoints and rtc recipes are counted in the skips list (reason
// "rtc-not-wired") and never expanded. Ordering is: recipes referenced by
// HintRecipes(asn) first (deduplicated, only existing ids), then the
// remaining recipes in document order; asn == "" skips the hints entirely.
//
// The expansion is fail-closed: any invalid candidate material (unknown
// server ref, empty host, port 0, path without a leading '/', wss recipe on
// a server without a wss endpoint) fails the whole expansion with an error
// naming the offending field. Revoked recipe/server ids cannot occur in a
// loader-verified document (the loader fail-closes on them); if one reaches
// this function through a hand-built Catalogue, it is skipped with reason
// "revoked" instead of expanded.
//
// TLS candidates carry Enabled: true and ServerName from the endpoint SNI
// (only when non-empty). Insecure is deliberately NOT set: the hydra CONFIRM
// frame authenticates the server against the static pubkey, but the TLS
// layer stays verification-capable; the fork's insecure default is applied
// by the outbound itself (see HydraOutboundOptions.TLS docs).

// ServerPubkeyLen is the size of a server static X25519 public key.
const ServerPubkeyLen = 32

// CandidatesFromCatalogue expands cat into adaptive outbound candidates.
// skips reports catalogue material that was seen but NOT expanded, one
// entry per item, each carrying a reason token ("rtc-not-wired", "revoked")
// so callers can filter on it. On any error both lists are nil.
func CandidatesFromCatalogue(cat *Catalogue, asn string) ([]option.HydraAdaptiveCandidateOptions, []string, error) {
	if cat == nil {
		return nil, nil, errors.New("hydra: catalogue expansion: catalogue is nil")
	}
	var (
		candidates []option.HydraAdaptiveCandidateOptions
		skips      []string
	)
	for _, rec := range orderedRecipes(cat, asn) {
		if rec.Transport != "wss" {
			skips = append(skips, fmt.Sprintf("recipe %s: %s", rec.ID, transportSkipReason(rec.Transport)))
			continue
		}
		if cat.IsRevoked(rec.ID) {
			skips = append(skips, fmt.Sprintf("recipe %s: revoked", rec.ID))
			continue
		}
		srv := findServer(cat, rec.Server)
		if srv == nil {
			return nil, nil, fmt.Errorf("hydra: catalogue expansion: recipe %q: unknown server ref %q", rec.ID, rec.Server)
		}
		if cat.IsRevoked(srv.ID) {
			skips = append(skips, fmt.Sprintf("recipe %s: server %s revoked", rec.ID, srv.ID))
			continue
		}
		wssEndpoints := 0
		for _, ep := range srv.Endpoints {
			switch ep.Transport {
			case "wss":
				wssEndpoints++
				if err := validateCatalogueEndpoint(rec.ID, ep); err != nil {
					return nil, nil, err
				}
				tls := &option.OutboundTLSOptions{Enabled: true}
				if ep.SNI != "" {
					tls.ServerName = ep.SNI
				}
				candidates = append(candidates, option.HydraAdaptiveCandidateOptions{
					ID: rec.ID,
					ServerOptions: option.ServerOptions{
						Server:     ep.Host,
						ServerPort: ep.Port,
					},
					Path: ep.Path,
					TLS:  tls,
				})
			case "rtc":
				skips = append(skips, fmt.Sprintf("endpoint %s/%s:%d%s: rtc-not-wired",
					srv.ID, ep.Host, ep.Port, ep.Path))
			}
		}
		if wssEndpoints == 0 {
			return nil, nil, fmt.Errorf("hydra: catalogue expansion: recipe %q: server %q has no wss endpoint", rec.ID, srv.ID)
		}
	}
	return candidates, skips, nil
}

// RecipeMaxFrame maps recipe params key "max_frame" onto the hydra session
// negotiation limit (wire frames 8/9/10). Mapping contract: the value must
// be a JSON number holding an INTEGER within 1024..=65536 inclusive
// (float64 is the only number kind encoding/json produces); absent key,
// non-number, fractional or out-of-range values all yield (0, false).
//
// There is no per-candidate option field for it: the caller applies the
// result to HydraOutboundOptions.NegotiateMaxFrame of the outbound that
// runs this recipe (one outbound per recipe at a time). Adding a
// NegotiateMaxFrame to HydraAdaptiveCandidateOptions is the plumbing work
// still pending in option/hydra.go.
func RecipeMaxFrame(cat *Catalogue, recipeID string) (uint32, bool) {
	if cat == nil {
		return 0, false
	}
	for i := range cat.Recipes {
		if cat.Recipes[i].ID != recipeID {
			continue
		}
		raw, ok := cat.Recipes[i].Params["max_frame"]
		if !ok {
			return 0, false
		}
		f, ok := raw.(float64)
		if !ok || f != math.Trunc(f) || f < 1024 || f > 65536 {
			return 0, false
		}
		return uint32(f), true
	}
	return 0, false
}

// ServerPubkey returns the 32-byte static X25519 public key of the server
// selected by recipeID. The caller places it into HydraOutboundOptions.Pubkey
// (base64) so the CONFIRM frame can authenticate the server. Errors on a nil
// catalogue, unknown recipe or unknown server ref; a malformed pubkey value
// is rejected here too (LoadAndVerifyCatalogue already enforces this, but
// hand-built documents must not slip through).
func ServerPubkey(cat *Catalogue, recipeID string) ([]byte, error) {
	if cat == nil {
		return nil, errors.New("hydra: server pubkey: catalogue is nil")
	}
	for i := range cat.Recipes {
		if cat.Recipes[i].ID == recipeID {
			srv := findServer(cat, cat.Recipes[i].Server)
			if srv == nil {
				return nil, fmt.Errorf("hydra: server pubkey: recipe %q: unknown server ref %q", recipeID, cat.Recipes[i].Server)
			}
			raw, err := base64.StdEncoding.DecodeString(srv.Pubkey)
			if err != nil || len(raw) != ServerPubkeyLen {
				return nil, fmt.Errorf("hydra: server pubkey: server %q: pubkey must be base64 of %d bytes", srv.ID, ServerPubkeyLen)
			}
			return raw, nil
		}
	}
	return nil, fmt.Errorf("hydra: server pubkey: unknown recipe %q", recipeID)
}

// orderedRecipes returns the recipes in expansion order: ASN-hinted first
// (deduplicated, ghost hint ids dropped — the loader rejects those anyway),
// then the rest in document order. asn == "" skips the hints.
func orderedRecipes(cat *Catalogue, asn string) []CatalogueRecipe {
	byID := make(map[string]*CatalogueRecipe, len(cat.Recipes))
	for i := range cat.Recipes {
		byID[cat.Recipes[i].ID] = &cat.Recipes[i]
	}
	var ids []string
	seen := make(map[string]bool, len(cat.Recipes))
	if asn != "" {
		for _, id := range cat.HintRecipes(asn) {
			if seen[id] {
				continue
			}
			if _, ok := byID[id]; !ok {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for i := range cat.Recipes {
		id := cat.Recipes[i].ID
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	out := make([]CatalogueRecipe, 0, len(ids))
	for _, id := range ids {
		out = append(out, *byID[id])
	}
	return out
}

func findServer(cat *Catalogue, id string) *CatalogueServer {
	for i := range cat.Servers {
		if cat.Servers[i].ID == id {
			return &cat.Servers[i]
		}
	}
	return nil
}

// transportSkipReason classifies a non-wss recipe transport for the skips list.
func transportSkipReason(transport string) string {
	if transport == "rtc" {
		return "rtc-not-wired"
	}
	return "unsupported-transport-" + transport
}

// validateCatalogueEndpoint re-checks the per-endpoint invariants for
// hand-built documents; the loader enforces the same checks on signed ones.
func validateCatalogueEndpoint(recipeID string, ep CatalogueEndpoint) error {
	if ep.Host == "" {
		return fmt.Errorf("hydra: catalogue expansion: recipe %q: endpoint :%d%s: empty host", recipeID, ep.Port, ep.Path)
	}
	if ep.Port == 0 {
		return fmt.Errorf("hydra: catalogue expansion: recipe %q: endpoint %s:%d%s: port 0", recipeID, ep.Host, ep.Port, ep.Path)
	}
	if len(ep.Path) == 0 || ep.Path[0] != '/' {
		return fmt.Errorf("hydra: catalogue expansion: recipe %q: endpoint %s:%d%s: path must start with '/'", recipeID, ep.Host, ep.Port, ep.Path)
	}
	return nil
}
