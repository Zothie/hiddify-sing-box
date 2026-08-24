//go:build with_quic

package juicity

// Return-side adapters: netproxy.Conn/PacketConn -> net.Conn/net.PacketConn.
//
// netproxy's connection interfaces are deliberately address-agnostic (no
// LocalAddr/RemoteAddr, and WriteTo takes a string). sing-box's routing and
// sniffing layers expect real net.Conn/net.PacketConn. These wrappers supply
// the missing methods using the destination we already know.

import (
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"

	M "github.com/sagernet/sing/common/metadata"
)

var _ net.Conn = (*netConnWrapper)(nil)

type netConnWrapper struct {
	netproxy.Conn
	destination M.Socksaddr
}

func (c *netConnWrapper) LocalAddr() net.Addr  { return M.Socksaddr{}.TCPAddr() }
func (c *netConnWrapper) RemoteAddr() net.Addr { return c.destination.TCPAddr() }

var _ net.PacketConn = (*netPacketConnWrapper)(nil)

type netPacketConnWrapper struct {
	netproxy.PacketConn
	destination M.Socksaddr
}

func (c *netPacketConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, nil, err
	}
	return n, net.UDPAddrFromAddrPort(addr), nil
}

func (c *netPacketConnWrapper) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, addr.String())
}

func (c *netPacketConnWrapper) LocalAddr() net.Addr { return M.Socksaddr{}.UDPAddr() }

// bindPacketConn presents a packet conn as a connected net.Conn, mirroring what
// sing's bufio.NewBindPacketConn does for the other QUIC outbounds.
type bindPacketConn struct {
	net.PacketConn
	destination M.Socksaddr
}

func newBindPacketConn(conn net.PacketConn, destination M.Socksaddr) net.Conn {
	return &bindPacketConn{PacketConn: conn, destination: destination}
}

func (c *bindPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *bindPacketConn) Write(b []byte) (int, error) {
	return c.PacketConn.WriteTo(b, c.destination.UDPAddr())
}

func (c *bindPacketConn) RemoteAddr() net.Addr             { return c.destination.UDPAddr() }
func (c *bindPacketConn) SetDeadline(t time.Time) error    { return c.PacketConn.SetDeadline(t) }
func (c *bindPacketConn) SetReadDeadline(t time.Time) error { return c.PacketConn.SetReadDeadline(t) }
func (c *bindPacketConn) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}
