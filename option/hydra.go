package option

// HydraOutboundOptions is the configuration for the hydra outbound
// (own VPN core: WS/TLS fronting + X25519/blake3/ChaCha20Poly1305 AEAD
// multiplexed sessions, wire-compatible with the Rust hydra client v0.9+).
type HydraOutboundOptions struct {
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
}
