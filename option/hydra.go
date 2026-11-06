package option

import "github.com/sagernet/sing/common/json/badoption"

type HydraAdaptiveCandidateOptions struct {
	ID                string `json:"id"`
	RecipeID          string `json:"recipe_id,omitempty"`
	Pubkey            string `json:"pubkey,omitempty"`
	NegotiateMaxFrame uint32 `json:"negotiate_max_frame,omitempty"`
	ServerOptions
	DialerOptions
	Path string              `json:"path,omitempty"`
	TLS  *OutboundTLSOptions `json:"tls,omitempty"`
	// Transport selects the candidate's wire transport: "wss" (default when
	// empty) or "rtc". Carried per candidate so a group can mix transports.
	Transport string `json:"transport,omitempty"`
}

type HydraAdaptiveOptions struct {
	// StatePath stores only a last-good hint scoped to the caller's physical network.
	StatePath          string                          `json:"state_path,omitempty"`
	NetworkKey         string                          `json:"network_key,omitempty"`
	PhysicalDNSServers []string                        `json:"physical_dns_servers,omitempty"`
	PhysicalInterface  string                          `json:"physical_interface,omitempty"`
	Candidates         []HydraAdaptiveCandidateOptions `json:"candidates"`
	ProofURL           string                          `json:"proof_url"`
	ProofBytes         int                             `json:"proof_bytes"`
	AttemptTimeout     badoption.Duration              `json:"attempt_timeout,omitempty"`
	Backoff            badoption.Duration              `json:"backoff,omitempty"`
	MaxBackoff         badoption.Duration              `json:"max_backoff,omitempty"`
	// RecoveryBudget bounds one full candidate epoch after a tunnel loss:
	// len(candidates) x AttemptTimeout must fit inside it or the config
	// build fails. Default 30s — the production mandate is a verified stable
	// connection restored within 30 s of a tunnel timeout whenever an
	// allowed recipe works and sits anywhere in the first epoch order.
	RecoveryBudget badoption.Duration `json:"recovery_budget,omitempty"`
	// ReferenceURLs lists up to three https origins that decide blackout:
	// after a full candidate epoch where no attempt reached a handshake, one
	// bounded HTTPS GET per reference runs through the physical dialer; when
	// all fail, the physical internet is assumed dead and candidate attempts
	// stop until a reference answers again. Empty (default) disables blackout
	// detection. Domain references need physical_dns_servers to resolve.
	ReferenceURLs []string `json:"reference_urls,omitempty"`
	// BlackoutRecheck is the wait between reference rechecks while blackout
	// is active. Default 60s; must be within [30s, 10m].
	BlackoutRecheck badoption.Duration `json:"blackout_recheck,omitempty"`
	// Coverage sweep (post-connection): after the proof passes, every
	// CoverageProbeURLs entry (https, max 64) is fetched THROUGH the verified
	// tunnel via its own session; percent answered = candidate coverage.
	// Acceptance keeps candidates within CoverageHysteresis points (0..100,
	// default 0 = must not be worse) of the best coverage seen so far, and
	// while the active tunnel is below 100% the outbound keeps prewarming
	// alternatives until coverage reaches 100% or a full candidate epoch
	// stops improving (the best candidate is kept). CoverageProbeTimeout
	// bounds one probe (default 5s, clamp 500ms..60s). With no probe URLs
	// the whole feature is off and Snapshot reports 0/0.
	CoverageProbeURLs    []string           `json:"coverage_probe_urls,omitempty"`
	CoverageProbeTimeout badoption.Duration `json:"coverage_probe_timeout,omitempty"`
	CoverageHysteresis   int                `json:"coverage_hysteresis,omitempty"`
}

// HydraOutboundOptions is the configuration for the hydra outbound
// (own VPN core: WS/TLS fronting + X25519/blake3/ChaCha20Poly1305 AEAD
// multiplexed sessions, wire-compatible with the Rust hydra client v0.9+).
type HydraOutboundOptions struct {
	Adaptive *HydraAdaptiveOptions `json:"adaptive,omitempty"`
	DialerOptions
	ServerOptions

	// Pubkey is the server static X25519 public key, base64 (standard
	// alphabet). Binds the session keys to the server (MITM-proof CONFIRM).
	Pubkey string `json:"pubkey"`

	// Path is the websocket path. Defaults to "/".
	Path string `json:"path,omitempty"`

	// TLS enables the wss transport fronting. When enabled, certificate
	// verification is always skipped (insecure) — this mirrors the Rust
	// client, whose server authentication is the pubkey-bound
	// "hydra-confirm" CONFIRM frame rather than the TLS layer.
	TLS *OutboundTLSOptions `json:"tls,omitempty"`

	// NegotiateMaxFrame enables session negotiation (frame types 8/9/10):
	// after CONFIRM and before the first OPEN the client offers this maximum
	// total frame size (payload + 17 B overhead). Valid 1024..=65536; 0
	// (default) disables negotiation and keeps the legacy wire format
	// byte-identical. A server that ignores the unknown frame type causes a
	// silent legacy fallback after 5 s; a REJECT never fails the tunnel.
	NegotiateMaxFrame uint32 `json:"negotiate_max_frame,omitempty"`

	// Adaptive-group plumbing, set by ray2sing when a hydra:// link carries
	// the adaptive query params (ag/pa/pb/pi/pd/at) and consumed by the core
	// config builder, which collapses every member sharing one AdaptiveGroup
	// into a single adaptive outbound (Adaptive set). They exist only between
	// the link parse and the builder; the runtime outbound never sees both
	// Adaptive and these set at once. All omitempty so plain links marshal
	// byte-identically to the pre-adaptive format.
	//
	// AdaptiveGroup names the adaptive group this link belongs to.
	AdaptiveGroup string `json:"adaptive_group,omitempty"`
	// AdaptiveProof is the https proof URL shared by the group.
	AdaptiveProof string `json:"adaptive_proof,omitempty"`
	// AdaptiveProofBytes is the proof response size in bytes (1024..1048576).
	AdaptiveProofBytes int `json:"adaptive_proof_bytes,omitempty"`
	// AdaptiveInterface pins the physical probes to one network interface.
	AdaptiveInterface string `json:"adaptive_interface,omitempty"`
	// AdaptiveDNS lists the physical-layer resolvers (ip:port, max 8).
	AdaptiveDNS []string `json:"adaptive_dns,omitempty"`
	// Transport is this link's wire transport ("wss", default, or "rtc").
	// For grouped links it is carried onto the candidate; a static (solo)
	// outbound keeps it on itself.
	Transport string `json:"transport,omitempty"`
}
