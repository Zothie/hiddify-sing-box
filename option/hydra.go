package option

import "github.com/sagernet/sing/common/json/badoption"

type HydraAdaptiveCandidateOptions struct {
	ID string `json:"id"`
	ServerOptions
	DialerOptions
	Path string              `json:"path,omitempty"`
	TLS  *OutboundTLSOptions `json:"tls,omitempty"`
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
}
