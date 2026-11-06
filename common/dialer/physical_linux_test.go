//go:build linux && !android

package dialer

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"os"
	"syscall"
	"testing"

	"github.com/sagernet/netlink"
	M "github.com/sagernet/sing/common/metadata"
)

func TestPhysicalClassification(t *testing.T) {
	for _, link := range []netlink.Link{&netlink.Tuntap{}, &netlink.Veth{}, &netlink.Bridge{}, &netlink.Dummy{}, &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp | net.FlagLoopback}}} {
		if physicalLink(link) {
			t.Fatalf("accepted %T", link)
		}
	}
	if !physicalLink(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "eth0", Flags: net.FlagUp}}) {
		t.Fatal("device rejected")
	}
}

func TestPhysicalConstructorFailClosed(t *testing.T) {
	for _, name := range []string{"", "lo", "missing-physical-interface"} {
		_, err := NewPhysical(context.Background(), PhysicalOptions{Interface: name})
		if !errors.Is(err, ErrPhysicalUnavailable) {
			t.Fatalf("%q: %v", name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewPhysical(ctx, PhysicalOptions{Interface: "eth0"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPhysicalRouteValidation(t *testing.T) {
	d := &PhysicalDialer{index: 2, routeGet: func(ip net.IP, opts *netlink.RouteGetOptions) ([]netlink.Route, error) {
		if opts.Oif != "eth0" {
			t.Fatal("unconstrained lookup")
		}
		return []netlink.Route{{LinkIndex: 9, Src: net.ParseIP("192.0.2.2")}}, nil
	}, name: "eth0"}
	if _, err := d.source(context.Background(), net.ParseIP("198.51.100.1")); !errors.Is(err, ErrPhysicalUnavailable) {
		t.Fatal(err)
	}
	d.routeGet = func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
		return []netlink.Route{{LinkIndex: 2, Src: net.ParseIP("192.0.2.2")}}, nil
	}
	if _, err := d.source(context.Background(), net.ParseIP("198.51.100.1")); err != nil {
		t.Fatal(err)
	}
}

func TestPhysicalBindingMissingInterface(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "socket")
	defer file.Close()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	d := &PhysicalDialer{name: "missing-phy"}
	if err := d.control("udp", "", raw); !errors.Is(err, ErrPhysicalUnavailable) {
		t.Fatal(err)
	}
}

func TestPhysicalPacketRejectsUnvalidatedPeer(t *testing.T) {
	p := &physicalPacketConn{peer: net.IPv4(192, 0, 2, 1)}
	if _, err := p.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 53}); !errors.Is(err, ErrPhysicalUnavailable) {
		t.Fatal(err)
	}
}

func TestPhysicalCancelDuringRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	d := &PhysicalDialer{index: 2, routeGet: func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
		calls++
		cancel()
		return []netlink.Route{{LinkIndex: 2, Src: net.ParseIP("192.0.2.2")}}, nil
	}}
	if _, err := d.source(ctx, net.ParseIP("198.51.100.1")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("lookups: %d", calls)
	}
}

// The pipe exercises real resolver DNS parsing, not kernel binding or routing.
func TestPhysicalDNSSequential(t *testing.T) {
	for _, mode := range []string{"answer", "fail", "cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			first := netip.MustParseAddrPort("192.0.2.53:53")
			second := netip.MustParseAddrPort("198.51.100.53:53")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var mu sync.Mutex
			seen := map[netip.AddrPort]int{}
			d := &PhysicalDialer{dns: []netip.AddrPort{first, second}, index: 2,
				routeGet: func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
					return []netlink.Route{{LinkIndex: 2, Src: net.ParseIP("192.0.2.2")}}, nil
				}}
			d.dnsDial = func(c context.Context, network string, endpoint netip.AddrPort) (net.Conn, error) {
				mu.Lock()
				seen[endpoint]++
				mu.Unlock()
				if endpoint != first && endpoint != second {
					t.Errorf("unexpected endpoint %v", endpoint)
				}
				if endpoint == first {
					if mode == "cancel" {
						cancel()
						return nil, context.Canceled
					}
					if mode == "timeout" {
						<-c.Done()
						return nil, c.Err()
					}
					return nil, errors.New("unavailable")
				}
				if mode == "fail" {
					return nil, errors.New("unavailable")
				}
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					var size [2]byte
					if _, err := io.ReadFull(server, size[:]); err != nil {
						return
					}
					packet := make([]byte, binary.BigEndian.Uint16(size[:]))
					if _, err := io.ReadFull(server, packet); err != nil {
						return
					}
					var request dnsmessage.Message
					if request.Unpack(packet) != nil {
						return
					}
					response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true}, Questions: request.Questions}
					for _, q := range request.Questions {
						if q.Type == dnsmessage.TypeA {
							response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}}})
						}
					}
					data, err := response.Pack()
					if err != nil {
						return
					}
					binary.BigEndian.PutUint16(size[:], uint16(len(data)))
					server.Write(append(size[:], data...))
				}()
				return client, nil
			}
			ip, err := d.destination(ctx, M.ParseSocksaddr("physical.invalid:443"))
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if mode == "fail" {
				if !errors.Is(err, ErrPhysicalUnavailable) {
					t.Fatal(err)
				}
			} else if err != nil || !ip.Equal(net.ParseIP("203.0.113.7")) {
				t.Fatalf("%v %v", ip, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[first] == 0 {
				t.Fatal("first endpoint skipped")
			}
			if mode == "cancel" {
				if seen[second] != 0 {
					t.Fatal("attempt after cancellation")
				}
			} else if seen[second] == 0 {
				t.Fatal("second endpoint skipped")
			}
		})
	}
}

func TestPhysicalDNSFailClosed(t *testing.T) {
	d := &PhysicalDialer{}
	if _, err := d.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.com:443")); !errors.Is(err, ErrPhysicalUnavailable) {
		t.Fatal(err)
	}
}
