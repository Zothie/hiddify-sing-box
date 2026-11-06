package hydra

import (
	"context"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HydraOutboundOptions](registry, C.TypeHydra, NewOutbound)
}

// Transport names for the option transport field ("wss" is the default when
// empty).
const (
	transportWSS = "wss"
	transportRTC = "rtc"
)

// normalizeTransport canonicalizes a transport value; "" means "wss".
func normalizeTransport(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return transportWSS
	}
	return s
}

var _ adapter.Outbound = (*Outbound)(nil)

// Outbound speaks the hydra protocol (own VPN core, WS/TLS fronting with
// AEAD-multiplexed sessions). One Tunnel is kept per outbound instance and
// rebuilt lazily whenever it dies — sing-box dials per connection, so no
// pool is needed (the Rust pool exists because its socks front is the only
// connection point).
type Outbound struct {
	outbound.Adapter
	logger   log.ContextLogger
	adaptive *adaptive.Coordinator

	dialer     N.Dialer
	serverAddr M.Socksaddr
	requestURL url.URL
	headers    http.Header
	pubkey     [32]byte
	// rtcTransport routes getTunnel through the rtc:// pump instead of the
	// ws handshake; dialer.ListenPacket provides the UDP socket then.
	rtcTransport bool

	// negotiateMaxFrame is the parent negotiate_max_frame option (0 =
	// disabled legacy behavior).
	negotiateMaxFrame uint32

	mu       sync.Mutex
	tunnel   *Tunnel
	isClosed bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HydraOutboundOptions) (adapter.Outbound, error) {
	if options.Adaptive != nil {
		return newAdaptiveOutbound(ctx, router, logger, tag, options)
	}
	return newStaticOutbound(ctx, logger, tag, options, nil)
}

func newStaticOutbound(ctx context.Context, logger log.ContextLogger, tag string, options option.HydraOutboundOptions, outboundDialer N.Dialer) (adapter.Outbound, error) {
	pubRaw, err := decodeB64(options.Pubkey)
	if err != nil {
		return nil, E.Cause(err, "decode hydra pubkey")
	}
	if len(pubRaw) != 32 {
		return nil, E.New("hydra pubkey must decode to 32 bytes, got ", len(pubRaw))
	}
	if outboundDialer == nil {
		outboundDialer, err = dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
		if err != nil {
			return nil, err
		}
	}
	if options.NegotiateMaxFrame != 0 && (options.NegotiateMaxFrame < maxFrameMin || options.NegotiateMaxFrame > maxFrameMax) {
		return nil, E.New("hydra: negotiate_max_frame must be 0 or 1024..=65536")
	}
	serverAddr := options.ServerOptions.Build()
	if serverAddr.Port == 0 {
		// Rust client defaults the port to 443 when the URL carries none.
		serverAddr.Port = 443
	}

	var transportDialer N.Dialer
	var requestURL url.URL
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	transport := normalizeTransport(options.Transport)
	if transport != transportWSS && transport != transportRTC {
		return nil, E.New("hydra: unknown transport ", options.Transport)
	}
	rtcTransport := transport == transportRTC
	if rtcTransport {
		// rtc:// has no websocket upgrade: no path, no TLS fronting. The
		// Rust client's rtc:// scheme likewise ignores them.
		if (options.Path != "" && options.Path != "/") || (options.TLS != nil && options.TLS.Enabled) {
			if logger != nil {
				logger.Debug("hydra rtc transport: ignoring path/tls options")
			}
		}
		transportDialer = outboundDialer // UDP socket via dialer.ListenPacket
	} else {
		transportDialer, err = buildTLSConfigAndDialer(ctx, logger, outboundDialer, serverAddr, options.TLS)
		if err != nil {
			return nil, err
		}

		path := options.Path
		if path == "" {
			path = "/"
		}
		if path[0] != '/' {
			path = "/" + path
		}
		// The TCP transport dials serverAddr; the HTTP Host header (and SNI, via
		// the TLS config) fronts the real hostname — mirrors the Rust
		// wss://sni@ip:port/path URL shape.
		hostHeader := serverAddr.AddrString()
		if options.TLS != nil && options.TLS.Enabled && options.TLS.ServerName != "" {
			hostHeader = options.TLS.ServerName
		}
		scheme := "ws"
		if options.TLS != nil && options.TLS.Enabled {
			scheme = "wss"
		}
		requestURL = url.URL{
			Scheme: scheme,
			Host:   net.JoinHostPort(hostHeader, strconv.Itoa(int(serverAddr.Port))),
			Path:   path,
		}
	}

	var pubkey [32]byte
	copy(pubkey[:], pubRaw)
	return &Outbound{
		Adapter:           outbound.NewAdapterWithDialerOptions(C.TypeHydra, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:            logger,
		dialer:            transportDialer,
		serverAddr:        serverAddr,
		requestURL:        requestURL,
		headers:           headers,
		pubkey:            pubkey,
		rtcTransport:      rtcTransport,
		negotiateMaxFrame: options.NegotiateMaxFrame,
	}, nil
}

// getTunnel returns the live tunnel, rebuilding it (serialized) when dead.
func (o *Outbound) getTunnel(ctx context.Context) (*Tunnel, error) {
	o.mu.Lock()
	if o.adaptive != nil {
		c := o.adaptive
		closed := o.isClosed
		o.mu.Unlock()
		if closed {
			return nil, E.New("hydra: outbound closed")
		}
		r, err := c.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		return r.(*Tunnel), nil
	}
	defer o.mu.Unlock()
	if o.isClosed {
		return nil, E.New("hydra: outbound closed")
	}
	if t := o.tunnel; t != nil && !t.IsDead() {
		return t, nil
	}
	// Kill the old tunnel so that its sessions fail fast and its pumps exit
	// even when it was stalled without being dead-flagged yet.
	if old := o.tunnel; old != nil {
		old.kill(nil)
	}
	dialFn := func(c context.Context) (net.Conn, error) {
		return o.dialer.DialContext(c, N.NetworkTCP, o.serverAddr)
	}
	var t *Tunnel
	var err error
	switch {
	case o.rtcTransport:
		t, err = connectTunnelRTC(ctx, func(c context.Context) (net.PacketConn, error) {
			return o.dialer.ListenPacket(c, o.serverAddr)
		}, o.pubkey[:], o.serverAddr.AddrPort(), o.logger, o.negotiateMaxFrame)
	case o.negotiateMaxFrame != 0:
		t, err = connectTunnelNegotiate(ctx, dialFn, &o.requestURL, o.headers, o.pubkey[:], o.logger, o.negotiateMaxFrame)
	default:
		t, err = connectTunnel(ctx, dialFn, &o.requestURL, o.headers, o.pubkey[:], o.logger)
	}
	if err != nil {
		return nil, err
	}
	o.tunnel = t
	return t, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		ctx, metadata := adapter.ExtendContext(ctx)
		metadata.Outbound = o.Tag()
		metadata.Destination = destination
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		// The Rust server has no stream-UDP mode; packet UDP goes through
		// ListenPacket. A udp_connect route action cannot be served.
		return nil, E.Extend(N.ErrUnknownNetwork, network+", hydra udp_connect is not supported")
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	t, err := o.getTunnel(ctx)
	if err != nil {
		return nil, err
	}
	s, err := t.openSession(ctx, socksaddrHost(destination), destination.Port)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	// Per-datagram targets are taken from WriteTo; the association-level
	// destination is informational for hydra.
	t, err := o.getTunnel(ctx)
	if err != nil {
		return nil, err
	}
	return t.openUDP(), nil
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	o.isClosed = true
	t, c := o.tunnel, o.adaptive
	o.tunnel = nil
	o.mu.Unlock()
	// Drop the registry entry before closing the coordinator so no reader
	// finds a tag whose state is about to flip to Closed. Static outbounds
	// never registered, so this is a no-op for them.
	adaptive.UnregisterOutbound(o.Tag())
	if c != nil {
		return c.Close()
	}
	if t != nil {
		t.kill(nil)
	}
	return nil
}
