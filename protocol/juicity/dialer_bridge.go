//go:build with_quic

package juicity

// Bridge between sing-box's dialer world and daeuniverse's netproxy world.
//
// WHY a bridge at all: the juicity client protocol is implemented once, well,
// in github.com/daeuniverse/outbound/protocol/juicity. Reimplementing the
// protocol inside sing-box would be several hundred lines of crypto/QUIC
// framing that we would then have to keep in sync with the server. Instead we
// reuse that client verbatim and only translate the two dialer interfaces.
//
// The translation is small because the interfaces are close:
//
//	sing-box  N.Dialer:  DialContext(ctx, network, M.Socksaddr) (net.Conn, error)
//	                     ListenPacket(ctx, M.Socksaddr) (net.PacketConn, error)
//	netproxy.Dialer:     DialContext(ctx, network, addr string) (netproxy.Conn, error)
//
// juicity only ever asks its nextDialer for a UDP association to the server
// (it runs QUIC over it), so the bridge only has to handle the UDP case
// correctly; TCP is passed through for completeness.

import (
	"context"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ netproxy.Dialer = (*singBridgeDialer)(nil)

// singBridgeDialer adapts a sing-box dialer so the juicity client can use it.
// Keeping sing-box as the underlying dialer is important: it is what applies
// the user's `detour`, routing marks, bind interface and "protect" behaviour on
// Android, so juicity inherits all of that for free.
type singBridgeDialer struct {
	dialer N.Dialer
}

func (d *singBridgeDialer) DialContext(ctx context.Context, network string, addr string) (netproxy.Conn, error) {
	// juicity encodes an optional fwmark into the network string; unwrap it.
	// We deliberately ignore the mark: sing-box's own dialer options already
	// carry routing_mark/bind_interface for this outbound.
	magic, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	destination := M.ParseSocksaddr(addr)
	switch magic.Network {
	case "udp":
		// juicity wants a packet conn it can drive QUIC over. sing-box hands
		// back a net.PacketConn; wrap it so it satisfies netproxy.PacketConn
		// (which also demands Read/Write, i.e. connected-socket semantics).
		packetConn, err := d.dialer.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return &bridgePacketConn{PacketConn: packetConn, destination: destination.UDPAddr()}, nil
	case "tcp":
		conn, err := d.dialer.DialContext(ctx, N.NetworkTCP, destination)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		return nil, E.New("juicity: unsupported network: ", magic.Network)
	}
}

var _ netproxy.PacketConn = (*bridgePacketConn)(nil)

// bridgePacketConn gives a net.PacketConn the connected-socket Read/Write and
// the netip-based ReadFrom/WriteTo that netproxy.PacketConn requires.
type bridgePacketConn struct {
	net.PacketConn
	destination *net.UDPAddr
}

func (c *bridgePacketConn) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *bridgePacketConn) Write(b []byte) (int, error) {
	return c.PacketConn.WriteTo(b, c.destination)
}

func (c *bridgePacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	return n, M.SocksaddrFromNet(addr).AddrPort(), nil
}

func (c *bridgePacketConn) WriteTo(p []byte, addr string) (int, error) {
	return c.PacketConn.WriteTo(p, M.ParseSocksaddr(addr).UDPAddr())
}

// SyscallConn / LocalAddr are surfaced when available so daeuniverse's
// FakeNetPacketConn can pick the optimised (OOB-capable) path.
func (c *bridgePacketConn) LocalAddr() net.Addr { return c.PacketConn.LocalAddr() }
