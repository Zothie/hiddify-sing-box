//go:build with_quic

// Package juicity implements a `juicity` outbound for sing-box.
//
// WHY: this fork's users sit behind Russian DPI that blocks QUIC proxy
// protocols one at a time. Hysteria2 and TUIC are both well-known and both get
// fingerprinted. juicity is a third, structurally different QUIC protocol
// (trojan-style metadata carried over QUIC streams, with a distinct
// authentication exchange), so it keeps working when the other two are killed.
// Upstream sing-box has no juicity support — issue #788 was opened and never
// merged — so it lives here in the fork.
//
// The protocol itself is NOT reimplemented: we reuse the mature client from
// github.com/daeuniverse/outbound/protocol/juicity (the same client used by
// dae/daed) and only adapt its dialer interface. See dialer_bridge.go.
package juicity

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/daeuniverse/outbound/netproxy"
	dprotocol "github.com/daeuniverse/outbound/protocol"
	djuicity "github.com/daeuniverse/outbound/protocol/juicity"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.JuicityOutboundOptions](registry, C.TypeJuicity, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	dialer netproxy.Dialer
	server string
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.JuicityOutboundOptions) (adapter.Outbound, error) {
	if options.UUID == "" {
		return nil, E.New("juicity: missing uuid")
	}
	serverAddr := options.ServerOptions.Build()

	// TLS. juicity always runs over TLS-in-QUIC. Private relays normally use a
	// self-signed certificate, which juicity handles via pinned_certchain_sha256
	// rather than by disabling verification outright.
	sni := serverAddr.AddrString()
	var insecure bool
	if options.TLS != nil {
		if options.TLS.ServerName != "" {
			sni = options.TLS.ServerName
		}
		insecure = options.TLS.Insecure
	}
	if options.PinnedCertchainSha256 != "" {
		// The dae juicity client verifies the pin itself; the stdlib verifier
		// must be bypassed or a self-signed chain would be rejected first.
		insecure = true
	}
	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"h3"}, // juicity's ALPN
		MinVersion:         tls.VersionTLS13,
	}

	congestion := options.CongestionControl
	if congestion == "" {
		congestion = "bbr" // juicity's client default; must be non-empty
	}

	// The underlying dialer stays sing-box's, so detour/routing_mark/bind_interface
	// and Android socket protection all still apply to juicity traffic.
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	juicityDialer, err := djuicity.NewDialer(&singBridgeDialer{dialer: outboundDialer}, dprotocol.Header{
		ProxyAddress: serverAddr.String(),
		SNI:          sni,
		Feature1:     congestion, // dae passes congestion control through Feature1
		TlsConfig:    tlsConfig,
		User:         options.UUID,
		Password:     options.Password,
		IsClient:     true,
	})
	if err != nil {
		return nil, E.Cause(err, "juicity: create client")
	}

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeJuicity, tag, options.Network.Build(), options.DialerOptions),
		logger:  logger,
		dialer:  juicityDialer,
		server:  serverAddr.String(),
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		conn, err := h.dialer.DialContext(ctx, "tcp", destination.String())
		if err != nil {
			return nil, err
		}
		// netproxy.Conn lacks LocalAddr/RemoteAddr that net.Conn requires.
		return &netConnWrapper{Conn: conn, destination: destination}, nil
	case N.NetworkUDP:
		conn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return newBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("juicity: unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.dialer.DialContext(ctx, "udp", destination.String())
	if err != nil {
		return nil, err
	}
	packetConn, ok := conn.(netproxy.PacketConn)
	if !ok {
		return nil, E.New("juicity: dialer did not return a packet conn")
	}
	return &netPacketConnWrapper{PacketConn: packetConn, destination: destination}, nil
}
