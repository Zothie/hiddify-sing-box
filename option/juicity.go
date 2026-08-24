package option

// JuicityOutboundOptions configures a `juicity` outbound.
//
// WHY this protocol exists in this fork:
// Russian DPI increasingly fingerprints and throttles individual QUIC-based
// proxy protocols one at a time. Having only Hysteria2/TUIC means a single
// successful fingerprint takes the whole tunnel down. juicity is a distinct
// QUIC protocol (different handshake and authentication shape, based on
// trojan-style metadata over QUIC streams), so it survives blocks that target
// TUIC/Hysteria2 specifically. Upstream sing-box never merged juicity support
// (sing-box issue #788), hence this fork-local implementation.
//
// The field set intentionally mirrors the juicity client config
// (see juicity/cmd/client/README.md) so that a `juicity://` share link maps
// one-to-one onto this struct.
type JuicityOutboundOptions struct {
	DialerOptions
	ServerOptions

	// UUID and Password are the credentials from the server's `users` map.
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`

	// CongestionControl is one of "bbr", "cubic", "new_reno".
	// juicity's client requires a non-empty value; Build defaults it to "bbr".
	CongestionControl string `json:"congestion_control,omitempty"`

	// PinnedCertchainSha256 is the base64/hex SHA-256 of the server certificate
	// chain, as produced by `juicity-server generate-certchain-hash`.
	// This is how juicity supports self-signed certificates without having to
	// blanket-disable verification (the common deployment on a private relay).
	PinnedCertchainSha256 string `json:"pinned_certchain_sha256,omitempty"`

	Network NetworkList `json:"network,omitempty"`

	OutboundTLSOptionsContainer
}
