package option

import "github.com/sagernet/sing/common/json/badoption"

type HydraAdaptiveCandidateOptions struct {
	ID string `json:"id"`
	ServerOptions
	DialerOptions
	Path string              `json:"path,omitempty"`
	TLS  *OutboundTLSOptions `json:"tls,omitempty"`
	// Transport selects the candidate's wire transport: "wss" (default when
	// empty) or "rtc". Carried per candidate so a group can mix transports.
	Transport string `json:"transport,omitempty"`
}

type HydraAdaptiveOptions struct {
	PhysicalDNSServers []string                        `json:"physical_dns_servers,omitempty"`
	PhysicalInterface  string                          `json:"physical_interface,omitempty"`
	Candidates         []HydraAdaptiveCandidateOptions `json:"candidates"`
	ProofURL           string                          `json:"proof_url"`
	ProofBytes         int                             `json:"proof_bytes"`
	AttemptTimeout     badoption.Duration              `json:"attempt_timeout,omitempty"`
	Backoff            badoption.Duration              `json:"backoff,omitempty"`
	MaxBackoff         badoption.Duration              `json:"max_backoff,omitempty"`
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
