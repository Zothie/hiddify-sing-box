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

	// Tuning axes (TUNING.md sweep). Every axis is optional: the zero value
	// falls back to the consumer's own baseline (the ws split path: the Rust
	// client's frag.rs tuning baseline; everything else: current behavior,
	// byte-identical to the pre-axes code). A signed catalogue recipe (params
	// keys below) or a hydra:// solo link fills them in; the effective-options
	// identity hash covers all of them, so two variants differing only in one
	// axis stay distinct candidates.
	//
	// First-flight split ranges (wss transport). Defaults mirror split.go =
	// the Rust frag.rs baseline: first segment uniform in 8..64 bytes, rest
	// uniform in 16..96, 1ms inter-segment pacing; a record at or under
	// firstMax is never split. Explicit values are clamped into 1..64 /
	// 1..96 / 0..50ms inside split.go. A catalogued rest_min fine enough to
	// exceed the server's AttackCheck read budget is skipped at expansion
	// (server-fatal shape, explicit unsafe-param reason).
	FragFirstMin uint32 `json:"frag_first_min,omitempty"`
	FragFirstMax uint32 `json:"frag_first_max,omitempty"`
	FragRestMin  uint32 `json:"frag_rest_min,omitempty"`
	FragRestMax  uint32 `json:"frag_rest_max,omitempty"`
	// FragSplitDelayMs sleeps between the segments of the first flight
	// (0 = the Rust default pacing of 1ms; explicit values clamp to 0..50).
	FragSplitDelayMs uint32 `json:"split_delay_ms,omitempty"`
	// Disorder sends the first ClientHello segment with IP TTL 1 (it dies at
	// the first router hop, so DPI never inspects the SNI) and restores the
	// saved TTL after the first write; a setsockopt failure falls back to
	// plain fragmentation. DisorderDelayMs (default 10ms, clamp 1..100)
	// paces the retransmission.
	Disorder        bool   `json:"disorder,omitempty"`
	DisorderDelayMs uint32 `json:"disorder_delay_ms,omitempty"`
	// PadBuckets replaces the frame-padding bucket ladder (applied to both
	// pad sites: the ws path and the rtc path). Validation is fail-closed:
	// strictly ascending, each 256..=65536, at most 8 entries (an
	// amplification bound against hostile catalogues).
	PadBuckets []uint32 `json:"pad_buckets,omitempty"`
	// MaxPad caps the random per-bucket slack (clamp 1..64, default 64 —
	// proto.rs MAX_PAD). BigPadMax bounds the extra padding of frames above
	// every bucket (clamp 1..4096, default 4096).
	MaxPad    uint32 `json:"max_pad,omitempty"`
	BigPadMax uint32 `json:"big_pad_max,omitempty"`
	// RTC engine axes (rtc transport). Zero = engine defaults (chunk 1150,
	// window 128, rto 250/3000ms, buffer 512, keepalive 5s); explicit values
	// clamp to the engine domains 256..1180 / 16..1024 / 50..500 /
	// 1000..10000 / 128..2048 / 2000..15000 (ms). These are server-coupled:
	// a chunk mismatch desyncs the framing, so catalogue variants must carry
	// server-agreed values.
	RTCChunk            uint32 `json:"rtc_chunk,omitempty"`
	RTCWindow           uint32 `json:"rtc_window,omitempty"`
	RTORtoMinMs         uint32 `json:"rto_min,omitempty"`
	RTORtoMaxMs         uint32 `json:"rto_max,omitempty"`
	RTCBufferCap        uint32 `json:"buffer_cap,omitempty"`
	RTCKeepaliveEveryMs uint32 `json:"keepalive_every,omitempty"`
	// TLS surface variants (sing-box TLS layer options threaded into the
	// child outbound's TLS config). Defaults = the current config (TLS 1.3
	// pin, http/1.1 ALPN). tls_server_name / SNI is already swept per
	// endpoint via the catalogue endpoint SNI field.
	TLSFragment   bool     `json:"tls_fragment,omitempty"`
	TLSMinVersion string   `json:"tls_min_version,omitempty"`
	TLSMaxVersion string   `json:"tls_max_version,omitempty"`
	TLSALPN       []string `json:"tls_alpn,omitempty"`
	// TLSFingerprint is the uTLS ClientHello fingerprint for the wss TLS
	// handshake (chrome / firefox / edge / safari / ios / android / 360 /
	// qq / random / randomized / chrome_psk* — the same vocabulary
	// sing-box's utls layer supports). Empty = the standard crypto/tls
	// handshake (unchanged default); an unknown name fails construction
	// (fail-closed). Requires a build with the with_utls tag — without it
	// the dial fails loudly rather than silently downgrading.
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	// HandshakeSpacingMs is the minimum spacing between handshake attempts
	// to the SAME server host inside an adaptive group (anti-salvo).
	// Effective spacing is the value plus a uniform 0..value jitter.
	// 0 = the 2000 ms default; values below 100 clamp to 100 ms, values
	// above 60000 clamp to 60 s.
	HandshakeSpacingMs uint32 `json:"handshake_spacing_ms,omitempty"`
	// DPI gate axes (rtc transport only — the Rust client gates the rtc
	// pump; wss stays ungated). DPIGateEnabled turns on the embedded
	// ClientSelfGate (100% verdict parity against the Rust-exported
	// fixtures); a raise rotates the session mask and rebuilds the tunnel.
	// Default false = today's ungated behavior. DPIGateThreshold is the
	// raise threshold (Rust HYDRA_DPI_THRESHOLD; default 0.5 when enabled
	// without a threshold); 0 with enabled=true is passed through VERBATIM
	// ("raise on everything" — the deliberate rebuild-path probe value), so
	// a config-builder round trip must not rely on the omitted-zero JSON
	// form for it. Valid domain 0..1; outside fails construction.
	DPIGateEnabled   bool    `json:"dpi_gate,omitempty"`
	DPIGateThreshold float32 `json:"dpi_threshold,omitempty"`
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
	// CatalogueASN orders catalogue recipe expansion for THIS group: recipes
	// hinted for the ASN (decimal AS number, from the asn= link param) expand
	// first so hint-first recovery sweeps the likely-working recipes first.
	// Empty (default) expands in document order. Advisory only — every
	// candidate still passes the runtime's own proof before use.
	CatalogueASN string `json:"catalogue_asn,omitempty"`
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
	// AdaptiveASN is the provider ASN hint carried by the asn= link param.
	// On a merged adaptive group it becomes HydraAdaptiveOptions.CatalogueASN
	// (catalogue recipe hint ordering); it is an ordering hint only, never
	// security. Stripped with the other plumbing on non-adaptive paths.
	AdaptiveASN string `json:"adaptive_asn,omitempty"`
	// Transport is this link's wire transport ("wss", default, or "rtc").
	// For grouped links it is carried onto the candidate; a static (solo)
	// outbound keeps it on itself.
	Transport string `json:"transport,omitempty"`

	// Tuning-axes passthrough (TUNING.md sweep), same fields and semantics
	// as HydraAdaptiveCandidateOptions: on a static (solo) outbound they
	// tune this outbound directly; on an adaptive group they are the GROUP
	// DEFAULTS every candidate inherits when its own axis is zero (the
	// candidate value wins). Zero everywhere = the byte-identical legacy
	// behavior. All omitempty so plain configs marshal unchanged.
	FragFirstMin        uint32   `json:"frag_first_min,omitempty"`
	FragFirstMax        uint32   `json:"frag_first_max,omitempty"`
	FragRestMin         uint32   `json:"frag_rest_min,omitempty"`
	FragRestMax         uint32   `json:"frag_rest_max,omitempty"`
	FragSplitDelayMs    uint32   `json:"split_delay_ms,omitempty"`
	Disorder            bool     `json:"disorder,omitempty"`
	DisorderDelayMs     uint32   `json:"disorder_delay_ms,omitempty"`
	PadBuckets          []uint32 `json:"pad_buckets,omitempty"`
	MaxPad              uint32   `json:"max_pad,omitempty"`
	BigPadMax           uint32   `json:"big_pad_max,omitempty"`
	RTCChunk            uint32   `json:"rtc_chunk,omitempty"`
	RTCWindow           uint32   `json:"rtc_window,omitempty"`
	RTORtoMinMs         uint32   `json:"rto_min,omitempty"`
	RTORtoMaxMs         uint32   `json:"rto_max,omitempty"`
	RTCBufferCap        uint32   `json:"buffer_cap,omitempty"`
	RTCKeepaliveEveryMs uint32   `json:"keepalive_every,omitempty"`
	TLSFragment         bool     `json:"tls_fragment,omitempty"`
	TLSMinVersion       string   `json:"tls_min_version,omitempty"`
	TLSMaxVersion       string   `json:"tls_max_version,omitempty"`
	TLSALPN             []string `json:"tls_alpn,omitempty"`
	// TLSFingerprint / HandshakeSpacingMs: same semantics as on the
	// candidate (see HydraAdaptiveCandidateOptions). Empty / zero = the
	// candidate's own value wins; on a candidate they are group defaults.
	TLSFingerprint     string `json:"tls_fingerprint,omitempty"`
	HandshakeSpacingMs uint32 `json:"handshake_spacing_ms,omitempty"`
	// DPI gate axes (rtc only), same contract as on the candidate:
	// enabled=false stays ungated and inherits the candidate's own axis;
	// the threshold rides verbatim when the gate is on (0 = deliberate
	// raise-on-everything probe value).
	DPIGateEnabled   bool    `json:"dpi_gate,omitempty"`
	DPIGateThreshold float32 `json:"dpi_threshold,omitempty"`
}
