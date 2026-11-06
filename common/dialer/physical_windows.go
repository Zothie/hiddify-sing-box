//go:build windows

package dialer

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
	"unsafe"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/windows"
)

// Windows socket option numbers from ws2ipdef.h. x/sys/windows does not
// export them, so they are defined here at their fixed protocol values.
const (
	sockoptIPUnicastIf   = 31 // IP_UNICAST_IF, level IPPROTO_IP
	sockoptIPv6UnicastIf = 31 // IPV6_UNICAST_IF, level IPPROTO_IPV6
	levelIPProto         = 0  // IPPROTO_IP
	levelIPProtoIPv6     = 41 // IPPROTO_IPV6
)

const afUnspec = 0

const gaaFlags = uint32(windows.GAA_FLAG_INCLUDE_ALL_INTERFACES)

// PhysicalDialer never falls back to a system resolver or an unbound socket.
// Binding and route validation cannot bypass hostile egress firewall rules.
// Route changes after validation remain a kernel-level race.
//
// Windows parity notes against the linux implementation:
//   - Interface-index binding via IP_UNICAST_IF (IPv4, interface index in
//     network byte order) and IPV6_UNICAST_IF (IPv6, host byte order), set
//     before bind/connect, is the hard guarantee. It replaces SO_BINDTODEVICE.
//   - Source-address selection is best-effort: the first DAD-preferred or
//     DAD-deprecated global unicast address of the matching family on the
//     validated adapter. The linux netlink route validation (single unicast
//     route, no multipath, pinned source) has no per-destination equivalent
//     reachable from these libraries.
//   - Windows exposes no bridge/bond master equivalent through
//     GetAdaptersAddresses, so enslaved adapters cannot be rejected, and
//     TAP-style virtual adapters report IfType 6 with a MAC address, making
//     them indistinguishable from real NICs. Loopback and tunnel-type
//     interfaces are rejected explicitly.
type PhysicalDialer struct {
	name    string
	index   uint32
	index6  uint32
	dnsDial func(context.Context, string, netip.AddrPort) (net.Conn, error)
	dns     []netip.AddrPort
}

var _ N.Dialer = (*PhysicalDialer)(nil)

type adapterSnapshot struct {
	name       string
	ifIndex    uint32
	ifIndex6   uint32
	operStatus uint32
	ifType     uint32
	v4         []net.IP
	v6         []net.IP
}

func utf16ToString(pointer *uint16) string {
	if pointer == nil {
		return ""
	}
	length := 0
	for cursor := pointer; *cursor != 0; cursor = (*uint16)(unsafe.Add(unsafe.Pointer(cursor), 2)) {
		length++
	}
	return syscall.UTF16ToString(unsafe.Slice(pointer, length))
}

func parseAdapter(aa *windows.IpAdapterAddresses) adapterSnapshot {
	snapshot := adapterSnapshot{
		name:       utf16ToString(aa.FriendlyName),
		ifIndex:    aa.IfIndex,
		ifIndex6:   aa.Ipv6IfIndex,
		operStatus: aa.OperStatus,
		ifType:     aa.IfType,
	}
	if snapshot.ifIndex6 == 0 {
		snapshot.ifIndex6 = aa.IfIndex
	}
	for address := aa.FirstUnicastAddress; address != nil; address = address.Next {
		ip := address.Address.IP()
		if ip == nil || (address.DadState != windows.IpDadStatePreferred && address.DadState != windows.IpDadStateDeprecated) {
			continue
		}
		stored := append(net.IP(nil), ip...)
		if stored.To4() != nil {
			snapshot.v4 = append(snapshot.v4, stored)
		} else {
			snapshot.v6 = append(snapshot.v6, stored)
		}
	}
	return snapshot
}

func enumerateAdapters() ([]adapterSnapshot, error) {
	var size uint32
	// The sizing probe is advisory; the retry loop below is the real contract.
	_ = windows.GetAdaptersAddresses(afUnspec, gaaFlags, 0, nil, &size)
	if size == 0 {
		size = 15 << 10
	}
	for attempt := 0; ; attempt++ {
		if attempt >= 8 {
			return nil, fmt.Errorf("%w: adapter enumeration did not settle", ErrPhysicalUnavailable)
		}
		buffer := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(afUnspec, gaaFlags, 0, aa, &size)
		if err == nil {
			snapshots := make([]adapterSnapshot, 0, 8)
			for cursor := aa; cursor != nil; cursor = cursor.Next {
				snapshots = append(snapshots, parseAdapter(cursor))
			}
			return snapshots, nil
		}
		if errors.Is(err, syscall.ERROR_BUFFER_OVERFLOW) && size != 0 {
			continue
		}
		return nil, fmt.Errorf("%w: adapter enumeration: %v", ErrPhysicalUnavailable, err)
	}
}

// physicalSnapshot mirrors the linux physicalLink gate: known index, known
// name, operationally up, not loopback, not a tunnel-type interface.
func physicalSnapshot(snapshot adapterSnapshot) bool {
	return snapshot.ifIndex > 0 &&
		snapshot.name != "" &&
		snapshot.operStatus == windows.IfOperStatusUp &&
		snapshot.ifType != windows.IF_TYPE_SOFTWARE_LOOPBACK &&
		snapshot.ifType != windows.IF_TYPE_TUNNEL
}

func findAdapter(name string) (adapterSnapshot, error) {
	snapshots, err := enumerateAdapters()
	if err != nil {
		return adapterSnapshot{}, err
	}
	for _, snapshot := range snapshots {
		if snapshot.name == name {
			return snapshot, nil
		}
	}
	return adapterSnapshot{}, fmt.Errorf("%w: adapter %q not found", ErrPhysicalUnavailable, name)
}

func NewPhysical(ctx context.Context, options PhysicalOptions) (*PhysicalDialer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Interface == "" {
		return nil, fmt.Errorf("%w: explicit interface required; automatic selection unsupported", ErrPhysicalUnavailable)
	}
	snapshot, err := findAdapter(options.Interface)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || !physicalSnapshot(snapshot) {
		return nil, fmt.Errorf("%w: invalid physical interface %q", ErrPhysicalUnavailable, options.Interface)
	}
	for _, server := range options.DNSServers {
		if !server.IsValid() || server.Port() == 0 || !server.Addr().IsGlobalUnicast() || server.Addr().Zone() != "" {
			return nil, fmt.Errorf("%w: invalid DNS endpoint", ErrPhysicalUnavailable)
		}
	}
	return &PhysicalDialer{name: options.Interface, index: snapshot.ifIndex, index6: snapshot.ifIndex6, dns: append([]netip.AddrPort(nil), options.DNSServers...)}, nil
}

// currentAdapter re-enumerates adapters and enforces that the stored adapter
// still exists, is still up, and kept both interface indexes, mirroring the
// linux LinkByName re-check inside controlContext.
func (d *PhysicalDialer) currentAdapter(ctx context.Context) (adapterSnapshot, error) {
	snapshot, err := findAdapter(d.name)
	if ctx.Err() != nil {
		return adapterSnapshot{}, ctx.Err()
	}
	if err != nil || !physicalSnapshot(snapshot) || snapshot.ifIndex != d.index || snapshot.ifIndex6 != d.index6 {
		return adapterSnapshot{}, fmt.Errorf("%w: interface changed", ErrPhysicalUnavailable)
	}
	return snapshot, nil
}

func (d *PhysicalDialer) source(ctx context.Context, is4 bool) (net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot, err := d.currentAdapter(ctx)
	if err != nil {
		return nil, err
	}
	candidates := snapshot.v4
	if !is4 {
		candidates = snapshot.v6
	}
	for _, candidate := range candidates {
		if (candidate.To4() != nil) == is4 && candidate.IsGlobalUnicast() {
			return append(net.IP(nil), candidate...), nil
		}
	}
	return nil, fmt.Errorf("%w: interface %q has no usable unicast source", ErrPhysicalUnavailable, d.name)
}

func addressIs4(address string) (bool, bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, false
	}
	return ip.To4() != nil, true
}

func (d *PhysicalDialer) control(network string, address string, raw syscall.RawConn) error {
	return d.controlContext(context.Background(), network, address, raw)
}

func (d *PhysicalDialer) controlContext(ctx context.Context, _ string, address string, raw syscall.RawConn) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := d.currentAdapter(ctx); err != nil {
		return err
	}
	is4, ok := addressIs4(address)
	if !ok {
		return fmt.Errorf("%w: unparseable socket address %q", ErrPhysicalUnavailable, address)
	}
	var bindErr error
	err := raw.Control(func(fd uintptr) {
		if is4 {
			// IP_UNICAST_IF takes the interface index in network byte order.
			bindErr = syscall.SetsockoptInt(syscall.Handle(fd), levelIPProto, sockoptIPUnicastIf, int(bits.ReverseBytes32(d.index)))
		} else {
			// IPV6_UNICAST_IF takes the interface index in host byte order.
			bindErr = syscall.SetsockoptInt(syscall.Handle(fd), levelIPProtoIPv6, sockoptIPv6UnicastIf, int(d.index6))
		}
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPhysicalUnavailable, err)
	}
	if bindErr != nil {
		return fmt.Errorf("%w: bind interface index: %v", ErrPhysicalUnavailable, bindErr)
	}
	return nil
}

func (d *PhysicalDialer) dialIP(ctx context.Context, network string, ip net.IP, port uint16) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	src, err := d.source(ctx, ip.To4() != nil)
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
			return nil, ctx.Err()
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
			if _, err := d.source(ctx, candidate.To4() != nil); err == nil {
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
// Each write rechecks adapter state. Other destinations require another socket.
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
	src, err := p.dialer.source(context.Background(), udp.IP.To4() != nil)
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
	src, err := d.source(ctx, ip.To4() != nil)
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
