//go:build linux && !android

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/netlink"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

// PhysicalDialer never falls back to a system resolver or an unbound socket.
// Binding and route validation cannot bypass hostile egress firewall rules.
// Route changes after validation remain a kernel-level race.
type PhysicalDialer struct {
	name     string
	index    int
	dnsDial  func(context.Context, string, netip.AddrPort) (net.Conn, error)
	dns      []netip.AddrPort
	routeGet func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error)
}

var _ N.Dialer = (*PhysicalDialer)(nil)

func physicalLink(link netlink.Link) bool {
	if link == nil || link.Type() != "device" {
		return false
	}
	a := link.Attrs()
	return a != nil && a.Index > 0 && a.Name != "" && a.MasterIndex == 0 && a.Flags&net.FlagUp != 0 && a.Flags&net.FlagLoopback == 0
}

func NewPhysical(ctx context.Context, options PhysicalOptions) (*PhysicalDialer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Interface == "" {
		return nil, fmt.Errorf("%w: explicit interface required; automatic selection unsupported", ErrPhysicalUnavailable)
	}
	link, err := netlink.LinkByName(options.Interface)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || !physicalLink(link) {
		return nil, fmt.Errorf("%w: invalid physical interface %q", ErrPhysicalUnavailable, options.Interface)
	}
	for _, server := range options.DNSServers {
		if !server.IsValid() || server.Port() == 0 || !server.Addr().IsGlobalUnicast() || server.Addr().Zone() != "" {
			return nil, fmt.Errorf("%w: invalid DNS endpoint", ErrPhysicalUnavailable)
		}
	}
	return &PhysicalDialer{name: options.Interface, index: link.Attrs().Index, dns: append([]netip.AddrPort(nil), options.DNSServers...), routeGet: netlink.RouteGetWithOptions}, nil
}

func (d *PhysicalDialer) source(ctx context.Context, ip net.IP) (net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !ip.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: non-unicast destination", ErrPhysicalUnavailable)
	}
	// Netlink has no cancellation API: checks cannot interrupt an in-flight syscall.
	routes, err := d.routeGet(ip, &netlink.RouteGetOptions{Oif: d.name})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err != nil || len(routes) != 1 {
		return nil, fmt.Errorf("%w: ambiguous or failed route lookup: %v", ErrPhysicalUnavailable, err)
	}
	r := routes[0]
	if r.LinkIndex != d.index || len(r.MultiPath) != 0 || (r.Type != 0 && r.Type != unix.RTN_UNICAST) || !r.Src.IsGlobalUnicast() || (r.Src.To4() != nil) != (ip.To4() != nil) {
		return nil, fmt.Errorf("%w: route is not physical unicast with usable source", ErrPhysicalUnavailable)
	}
	// Repeat the exact lookup constrained by both output interface and source.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	routes, err = d.routeGet(ip, &netlink.RouteGetOptions{Oif: d.name, SrcAddr: r.Src})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err != nil || len(routes) != 1 || routes[0].LinkIndex != d.index || len(routes[0].MultiPath) != 0 || (routes[0].Type != 0 && routes[0].Type != unix.RTN_UNICAST) {
		return nil, fmt.Errorf("%w: source route validation failed", ErrPhysicalUnavailable)
	}
	return append(net.IP(nil), r.Src...), nil
}

func (d *PhysicalDialer) control(network string, address string, raw syscall.RawConn) error {
	return d.controlContext(context.Background(), network, address, raw)
}

func (d *PhysicalDialer) controlContext(ctx context.Context, _ string, _ string, raw syscall.RawConn) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	link, lookupErr := netlink.LinkByName(d.name)
	if err := ctx.Err(); err != nil {
		return err
	}
	if lookupErr != nil || !physicalLink(link) || link.Attrs().Index != d.index {
		return fmt.Errorf("%w: interface changed", ErrPhysicalUnavailable)
	}
	var bindErr error
	err := raw.Control(func(fd uintptr) {
		bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, d.name)
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPhysicalUnavailable, err)
	}
	if bindErr != nil {
		return fmt.Errorf("%w: bind device: %v", ErrPhysicalUnavailable, bindErr)
	}
	return nil
}

func (d *PhysicalDialer) dialIP(ctx context.Context, network string, ip net.IP, port uint16) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	src, err := d.source(ctx, ip)
	if err != nil {
		return nil, err
	}
	var local net.Addr
	switch network {
	case "tcp", "tcp4", "tcp6":
		local = &net.TCPAddr{IP: src}
	case "udp", "udp4", "udp6":
		local = &net.UDPAddr{IP: src}
	default:
		return nil, fmt.Errorf("%w: unsupported network", ErrPhysicalUnavailable)
	}
	nd := net.Dialer{LocalAddr: local, ControlContext: func(c context.Context, network, address string, raw syscall.RawConn) error {
		return d.controlContext(c, network, address, raw)
	}}
	return nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), fmt.Sprint(port)))
}

func (d *PhysicalDialer) destination(ctx context.Context, address M.Socksaddr) (net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !address.IsFqdn() {
		return net.IP(address.Addr.AsSlice()), nil
	}
	if len(d.dns) == 0 {
		return nil, fmt.Errorf("%w: domain requires explicit physical DNS", ErrPhysicalUnavailable)
	}
	for _, server := range d.dns {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempt, cancel := context.WithTimeout(ctx, time.Second)
		resolver := net.Resolver{PreferGo: true, Dial: func(c context.Context, network, _ string) (net.Conn, error) {
			// Ignore system endpoints. The seam tests DNS policy, not kernel bypass.
			if d.dnsDial != nil {
				return d.dnsDial(c, network, server)
			}
			return d.dialIP(c, network, net.IP(server.Addr().AsSlice()), server.Port())
		}}
		addresses, err := resolver.LookupNetIP(attempt, "ip", strings.TrimSuffix(address.Fqdn, ".")+".")
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			continue
		}
		for _, ip := range addresses {
			candidate := net.IP(ip.AsSlice())
			if _, err := d.source(ctx, candidate); err == nil {
				return candidate, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}
	return nil, ErrPhysicalUnavailable
}

func (d *PhysicalDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	ip, err := d.destination(ctx, address)
	if err != nil {
		return nil, err
	}
	return d.dialIP(ctx, network, ip, address.Port)
}

// physicalPacketConn restricts writes to the destination whose source was bound.
// Each write rechecks policy routing. Other destinations require another socket.
type physicalPacketConn struct {
	net.PacketConn
	peer     net.IP
	sourceIP net.IP
	dialer   *PhysicalDialer
}

func (p *physicalPacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp.Zone != "" || !udp.IP.Equal(p.peer) {
		return 0, fmt.Errorf("%w: unvalidated packet destination", ErrPhysicalUnavailable)
	}
	src, err := p.dialer.source(context.Background(), udp.IP)
	if err != nil {
		return 0, err
	}
	if !src.Equal(p.sourceIP) {
		return 0, fmt.Errorf("%w: source changed", ErrPhysicalUnavailable)
	}
	return p.PacketConn.WriteTo(data, addr)
}

func (d *PhysicalDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ip, err := d.destination(ctx, destination)
	if err != nil {
		return nil, err
	}
	src, err := d.source(ctx, ip)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		return d.controlContext(ctx, network, address, raw)
	}}
	conn, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort(src.String(), "0"))
	if err != nil {
		return nil, err
	}
	return &physicalPacketConn{PacketConn: conn, peer: ip, dialer: d, sourceIP: src}, nil
}
