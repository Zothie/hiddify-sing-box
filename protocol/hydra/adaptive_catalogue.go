package hydra

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// Catalogue -> adaptive outbound candidate expansion.
//
// CandidatesFromCatalogue turns a VERIFIED catalogue (see
// LoadAndVerifyCatalogue) into option.HydraAdaptiveCandidateOptions entries
// for the hydra adaptive outbound. WSS and RTC recipes expand only matching
// endpoints. Unsupported params and requirements are reported and skipped.
// Ordering is: recipes referenced by
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
// entry per item, each carrying an unsupported-axis or revoked reason token
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
		if rec.Transport != "wss" && rec.Transport != "rtc" {
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
		unsupported := false
		for key := range rec.Params {
			if !catalogueAxisKeys[key] {
				skips = append(skips, fmt.Sprintf("recipe %s: unsupported-param-%s", rec.ID, key))
				unsupported = true
			}
		}
		for key := range rec.Requires {
			skips = append(skips, fmt.Sprintf("recipe %s: unsupported-requirement-%s", rec.ID, key))
			unsupported = true
		}
		if unsupported {
			continue
		}
		axes, axErr := parseRecipeAxes(rec.Params)
		if axErr != nil {
			if errors.Is(axErr, errUnsafeFragRest) {
				skips = append(skips, fmt.Sprintf("recipe %s: unsafe-param-frag_rest_min", rec.ID))
				continue
			}
			return nil, nil, fmt.Errorf("hydra: recipe %q: %w", rec.ID, axErr)
		}
		maxFrame, validFrame := RecipeMaxFrame(cat, rec.ID)
		if _, present := rec.Params["max_frame"]; present && !validFrame {
			return nil, nil, fmt.Errorf("hydra: recipe %q: invalid max_frame", rec.ID)
		}
		if _, err := ServerPubkey(cat, rec.ID); err != nil {
			return nil, nil, err
		}
		wssEndpoints := 0
		for _, ep := range srv.Endpoints {
			if ep.Transport != rec.Transport {
				continue
			}
			switch ep.Transport {
			case "wss", "rtc":
				wssEndpoints++
				if err := validateCatalogueEndpoint(rec.ID, ep); err != nil {
					return nil, nil, err
				}
				tls := &option.OutboundTLSOptions{Enabled: true}
				if ep.SNI != "" {
					tls.ServerName = ep.SNI
				}
				if rec.Transport == "rtc" {
					tls = nil
				}
				encoded, err := json.Marshal(ep)
				if err != nil {
					return nil, nil, err
				}
				// Struct JSON fixes field order; neither encoded recipe IDs nor hex
				// digests contain the ':' separator. Never mix raw recipe IDs here.
				id := fmt.Sprintf("catalogue:%s:%x", base64.RawURLEncoding.EncodeToString([]byte(rec.ID)), sha256.Sum256(encoded))
				candidates = append(candidates, option.HydraAdaptiveCandidateOptions{
					ID: id, RecipeID: rec.ID, Pubkey: srv.Pubkey, NegotiateMaxFrame: maxFrame, Transport: rec.Transport,
					ServerOptions: option.ServerOptions{
						Server:     ep.Host,
						ServerPort: ep.Port,
					},
					Path: ep.Path,
					TLS:  tls,
					// Tuning axes from the recipe params: every axis flows
					// into the candidate (and thereby into the
					// effective-options identity hash), so two variants
					// differing only in one axis expand as two candidates.
					FragFirstMin:        axes.fragFirstMin,
					FragFirstMax:        axes.fragFirstMax,
					FragRestMin:         axes.fragRestMin,
					FragRestMax:         axes.fragRestMax,
					FragSplitDelayMs:    axes.splitDelayMs,
					Disorder:            axes.disorder,
					DisorderDelayMs:     axes.disorderDelayMs,
					PadBuckets:          axes.padBuckets,
					MaxPad:              axes.maxPad,
					BigPadMax:           axes.bigPadMax,
					RTCChunk:            axes.rtcChunk,
					RTCWindow:           axes.rtcWindow,
					RTORtoMinMs:         axes.rtoMinMs,
					RTORtoMaxMs:         axes.rtoMaxMs,
					RTCBufferCap:        axes.bufferCap,
					RTCKeepaliveEveryMs: axes.keepaliveEveryMs,
					TLSFragment:         axes.tlsFragment,
					TLSMinVersion:       axes.tlsMinVersion,
					TLSMaxVersion:       axes.tlsMaxVersion,
					TLSALPN:             axes.tlsALPN,
					DPIGateEnabled:      axes.dpiGate,
					DPIGateThreshold:    axes.dpiThreshold,
				})
			}
		}
		if wssEndpoints == 0 {
			return nil, nil, fmt.Errorf("hydra: catalogue expansion: recipe %q: server %q has no %s endpoint", rec.ID, srv.ID, rec.Transport)
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
// Expansion carries this value in each candidate's NegotiateMaxFrame.
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

// catalogueAxisKeys is the recipe-params vocabulary the expansion
// understands (TUNING.md sweep). Keys outside this set produce an explicit
// unsupported-param-<key> skip entry — never a silent ignore. Values are
// scalars per the catalogue schema (number or string); list-shaped axes
// (pad_buckets, tls_alpn) ride comma-separated strings.
var catalogueAxisKeys = map[string]bool{
	"max_frame":         true,
	"frag_first_min":    true,
	"frag_first_max":    true,
	"frag_rest_min":     true,
	"frag_rest_max":     true,
	"split_delay_ms":    true,
	"disorder":          true,
	"disorder_delay_ms": true,
	"pad_buckets":       true,
	"max_pad":           true,
	"big_pad_max":       true,
	"rtc_chunk":         true,
	"rtc_window":        true,
	"rto_min":           true,
	"rto_max":           true,
	"buffer_cap":        true,
	"keepalive_every":   true,
	"tls_fragment":      true,
	"tls_min_version":   true,
	"tls_max_version":   true,
	"tls_alpn":          true,
	"dpi_gate":          true,
	"dpi_threshold":     true,
}

// recipeAxes is the parsed tuning-axis payload of one recipe's params.
type recipeAxes struct {
	fragFirstMin, fragFirstMax   uint32
	fragRestMin, fragRestMax     uint32
	splitDelayMs                 uint32
	disorder                     bool
	disorderDelayMs              uint32
	padBuckets                   []uint32
	maxPad, bigPadMax            uint32
	rtcChunk, rtcWindow          uint32
	rtoMinMs, rtoMaxMs           uint32
	bufferCap, keepaliveEveryMs  uint32
	tlsFragment                  bool
	tlsMinVersion, tlsMaxVersion string
	tlsALPN                      []string
	dpiGate                      bool
	dpiThreshold                 float32
}

// Catalogue-axis clamp domains (same clamps the runtime applies; zero keeps
// the engine default, so only positive out-of-domain values clamp).
const (
	clampFirstMin, clampFirstMax             = 1, 64
	clampRestMin, clampRestMax               = 1, 96
	clampSplitDelayMaxMs                     = 50
	clampDisorderDelayMaxMs                  = 100
	clampMaxPadMax                           = 64
	clampBigPadMax                           = 4096
	clampRTCChunkMin, clampRTCChunkMax       = 256, 1180
	clampRTCWindowMin, clampRTCWindowMax     = 16, 1024
	clampRTOMinMinMs, clampRTOMinMaxMs       = 50, 500
	clampRTOMaxMinMs, clampRTOMaxMaxMs       = 1000, 10000
	clampBufferCapMin, clampBufferCapMax     = 128, 2048
	clampKeepaliveMinMs, clampKeepaliveMaxMs = 2000, 15000
)

// Server-fatal frag-shape guard (measured against the real Rust server's
// tungstenite 0.24 AttackCheck, handshake/machine.rs): an upgrade arriving
// in more than attackCheckReadLimit reads averaging under 128 B is answered
// with an instant mid-upgrade RST — no client-side error hint. The catalogue
// keeps the worst-case piece count of a attackCheckFlightB first flight at
// or under attackCheckGuardPieces: one first segment (<=64 B) plus
// ceil((flight-firstMax)/rest_min). For firstMax 64 the rest floor lands at
// 11; anything below is skipped with an explicit unsafe-param reason instead
// of failing the whole expansion, so one bad recipe cannot silence every
// other candidate.
const (
	attackCheckReadLimit   = 64
	attackCheckGuardPieces = 48
	attackCheckFlightB     = 512
)

// errUnsafeFragRest marks a recipe whose rest ladder can trip the server's
// AttackCheck on every connect; the expansion turns it into an explicit
// recipe-level skip.
var errUnsafeFragRest = errors.New("frag_rest_min can exceed the server AttackCheck read budget (server-fatal shape)")

// attackCheckSafe reports whether a firstMax/restMin pair keeps the
// worst-case piece count within the guard budget. restMin == 0 means the
// axis is absent (the Rust baseline rest floor of 16 applies) — always safe.
func attackCheckSafe(firstMax, restMin uint32) bool {
	if restMin == 0 {
		return true
	}
	first := firstMax
	if first == 0 || first > splitFirstClampMax {
		first = splitFirstClampMax
	}
	if int(first) >= attackCheckFlightB {
		return true
	}
	pieces := 1 + (attackCheckFlightB-int(first)+int(restMin)-1)/int(restMin)
	return pieces <= attackCheckGuardPieces
}

// parseRecipeAxes extracts the tuning axes from a recipe's params map.
// Fail-closed: a KNOWN key with a malformed value (fractional, negative,
// wrong kind, malformed pad ladder) fails the expansion with an error; the
// caller has already skipped recipes carrying UNKNOWN keys. Numeric values
// are clamped into their engine domains; zero keeps the engine default.
func parseRecipeAxes(params map[string]any) (recipeAxes, error) {
	var ax recipeAxes
	u32 := func(key string, lo, hi uint32) (uint32, error) {
		v, present, err := uintParam(params, key)
		if err != nil || !present {
			return 0, err
		}
		if v < lo {
			v = lo
		}
		if v > hi {
			v = hi
		}
		return v, nil
	}
	var err error
	if ax.fragFirstMin, err = u32("frag_first_min", clampFirstMin, clampFirstMax); err != nil {
		return ax, err
	}
	if ax.fragFirstMax, err = u32("frag_first_max", clampFirstMin, clampFirstMax); err != nil {
		return ax, err
	}
	if ax.fragRestMin, err = u32("frag_rest_min", clampRestMin, clampRestMax); err != nil {
		return ax, err
	}
	if ax.fragRestMax, err = u32("frag_rest_max", clampRestMin, clampRestMax); err != nil {
		return ax, err
	}
	// AttackCheck guard: a rest ladder fine enough to exceed the server's
	// read budget RSTs every connect. Recipe-level unsafe (skip), not
	// expansion-fatal.
	if !attackCheckSafe(ax.fragFirstMax, ax.fragRestMin) {
		return ax, errUnsafeFragRest
	}
	if ax.splitDelayMs, err = u32("split_delay_ms", 0, clampSplitDelayMaxMs); err != nil {
		return ax, err
	}
	if ax.disorder, err = boolParam(params, "disorder"); err != nil {
		return ax, err
	}
	if ax.disorderDelayMs, err = u32("disorder_delay_ms", 0, clampDisorderDelayMaxMs); err != nil {
		return ax, err
	}
	if raw, present := params["pad_buckets"]; present {
		buckets, perr := padBucketsParam(raw)
		if perr != nil {
			return ax, perr
		}
		if verr := validatePadBuckets(buckets); verr != nil {
			return ax, verr
		}
		ax.padBuckets = buckets
	}
	if ax.maxPad, err = u32("max_pad", 0, clampMaxPadMax); err != nil {
		return ax, err
	}
	if ax.bigPadMax, err = u32("big_pad_max", 0, clampBigPadMax); err != nil {
		return ax, err
	}
	if ax.rtcChunk, err = u32("rtc_chunk", clampRTCChunkMin, clampRTCChunkMax); err != nil {
		return ax, err
	}
	if ax.rtcWindow, err = u32("rtc_window", clampRTCWindowMin, clampRTCWindowMax); err != nil {
		return ax, err
	}
	if ax.rtoMinMs, err = u32("rto_min", clampRTOMinMinMs, clampRTOMinMaxMs); err != nil {
		return ax, err
	}
	if ax.rtoMaxMs, err = u32("rto_max", clampRTOMaxMinMs, clampRTOMaxMaxMs); err != nil {
		return ax, err
	}
	if ax.bufferCap, err = u32("buffer_cap", clampBufferCapMin, clampBufferCapMax); err != nil {
		return ax, err
	}
	if ax.keepaliveEveryMs, err = u32("keepalive_every", clampKeepaliveMinMs, clampKeepaliveMaxMs); err != nil {
		return ax, err
	}
	if ax.tlsFragment, err = boolParam(params, "tls_fragment"); err != nil {
		return ax, err
	}
	if ax.tlsMinVersion, err = strParam(params, "tls_min_version"); err != nil {
		return ax, err
	}
	if ax.tlsMaxVersion, err = strParam(params, "tls_max_version"); err != nil {
		return ax, err
	}
	if raw, present := params["tls_alpn"]; present {
		s, ok := raw.(string)
		if !ok {
			return ax, fmt.Errorf("param tls_alpn must be a comma-separated string")
		}
		for _, item := range strings.Split(s, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				ax.tlsALPN = append(ax.tlsALPN, item)
			}
		}
	}
	if ax.dpiGate, err = boolParam(params, "dpi_gate"); err != nil {
		return ax, err
	}
	if raw, present := params["dpi_threshold"]; present {
		f, ok := raw.(float64)
		if !ok || f < 0 || f > 1 {
			return ax, fmt.Errorf("param dpi_threshold must be a number in 0..1")
		}
		// Verbatim, including an explicit 0 (deliberate raise-on-everything).
		ax.dpiThreshold = float32(f)
	} else if ax.dpiGate {
		// An enabled gate without a threshold bakes the Rust default here,
		// so the candidate struct (and the identity JSON) carries a concrete
		// value distinct from the explicit-0 probe.
		ax.dpiThreshold = dpiGateDefaultThreshold
	}
	return ax, nil
}

// uintParam reads one numeric axis: absent = (0,false,nil); a JSON number
// must be a non-negative integer (float64 is the only number kind
// encoding/json produces); anything else fails.
func uintParam(params map[string]any, key string) (uint32, bool, error) {
	raw, present := params[key]
	if !present {
		return 0, false, nil
	}
	f, ok := raw.(float64)
	if !ok || f != math.Trunc(f) || f < 0 {
		return 0, false, fmt.Errorf("param %s must be a non-negative integer", key)
	}
	if f > math.MaxUint32 {
		return 0, false, fmt.Errorf("param %s overflows uint32", key)
	}
	return uint32(f), true, nil
}

// boolParam reads one boolean axis. The catalogue schema allows only numbers
// and strings, so truth rides 1/0 (any non-zero number) or the strings
// "true"/"false"/"1"/"0"; anything else fails.
func boolParam(params map[string]any, key string) (bool, error) {
	raw, present := params[key]
	if !present {
		return false, nil
	}
	switch v := raw.(type) {
	case float64:
		if v != math.Trunc(v) {
			return false, fmt.Errorf("param %s must be an integer flag", key)
		}
		return v != 0, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1":
			return true, nil
		case "false", "0":
			return false, nil
		}
		return false, fmt.Errorf("param %s must be true/false/1/0", key)
	default:
		return false, fmt.Errorf("param %s must be a number or string", key)
	}
}

// strParam reads one string axis; a non-string value fails.
func strParam(params map[string]any, key string) (string, error) {
	raw, present := params[key]
	if !present {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("param %s must be a string", key)
	}
	return s, nil
}

// padBucketsParam decodes the pad_buckets axis: a single number is a
// one-entry ladder; a string is a comma-separated ladder. Bucket-member
// validation runs in validatePadBuckets (fail-closed, audit F10).
func padBucketsParam(raw any) ([]uint32, error) {
	switch v := raw.(type) {
	case float64:
		if v != math.Trunc(v) || v < 0 {
			return nil, fmt.Errorf("param pad_buckets must be integers")
		}
		return []uint32{uint32(v)}, nil
	case string:
		var buckets []uint32
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			n, err := strconv.ParseUint(item, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("param pad_buckets entry %q is not an integer", item)
			}
			buckets = append(buckets, uint32(n))
		}
		return buckets, nil
	default:
		return nil, fmt.Errorf("param pad_buckets must be a number or a comma-separated string")
	}
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

// transportSkipReason classifies an unsupported recipe transport.
func transportSkipReason(transport string) string {
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
