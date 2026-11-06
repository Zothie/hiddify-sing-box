package dialer

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type protectionPlatform struct{ adapter.PlatformInterface }

func (*protectionPlatform) UsePlatformAutoDetectInterfaceControl() bool { return true }

type protectionNetwork struct {
	adapter.NetworkManager
	protect control.Func
	auto    bool
}

func (*protectionNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (*protectionNetwork) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (n *protectionNetwork) AutoDetectInterface() bool              { return n.auto }
func (n *protectionNetwork) ProtectFunc() control.Func              { return n.protect }
func (*protectionNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }

func TestRequiredProtectionWithoutAutoDetect(t *testing.T) {
	for _, fail := range []bool{false, true} {
		for _, network := range []string{"tcp", "udp", "listen"} {
			t.Run(network+map[bool]string{false: "/success", true: "/failure"}[fail], func(t *testing.T) {
				calls := 0
				denied := errors.New("protection denied")
				ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), &protectionPlatform{})
				ctx = service.ContextWith[adapter.NetworkManager](ctx, &protectionNetwork{protect: func(_, _ string, raw syscall.RawConn) error {
					calls++
					if err := raw.Control(func(fd uintptr) {
						if fd == 0 {
							t.Error("invalid descriptor")
						}
					}); err != nil {
						return err
					}
					if fail {
						return denied
					}
					return nil
				}})
				d, err := NewDefault(ctx, option.DialerOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if d.networkStrategy != nil {
					t.Fatal("protection enabled network strategy")
				}
				var closer interface{ Close() error }
				if network == "listen" {
					closer, err = d.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:53"))
				} else {
					var addr string
					if network == "tcp" {
						l, e := net.Listen("tcp4", "127.0.0.1:0")
						if e != nil {
							t.Fatal(e)
						}
						defer l.Close()
						addr = l.Addr().String()
					} else {
						addr = "127.0.0.1:53"
					}
					closer, err = d.DialContext(ctx, network, M.ParseSocksaddr(addr))
				}
				if err == nil {
					defer closer.Close()
				}
				if calls != 1 {
					t.Fatalf("protection calls = %d, want 1", calls)
				}
				if fail && !errors.Is(err, denied) {
					t.Fatalf("error = %v, want protection denial", err)
				}
				if !fail && err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestProtectionPreservesAutoDetectStrategy(t *testing.T) {
	calls := 0
	ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), &protectionPlatform{})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &protectionNetwork{auto: true, protect: func(_, _ string, _ syscall.RawConn) error { calls++; return nil }})
	d, err := NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if d.networkStrategy == nil || !d.defaultNetworkStrategy {
		t.Fatal("autodetect strategy lost")
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err = d.WireGuardControl()("udp4", "127.0.0.1:53", raw); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("protection calls = %d, want 1", calls)
	}
}

func TestNoPlatformDoesNotRequireProtection(t *testing.T) {
	for _, manager := range []adapter.NetworkManager{nil, &protectionNetwork{}} {
		ctx := context.Background()
		if manager != nil {
			ctx = service.ContextWith[adapter.NetworkManager](ctx, manager)
		}
		d, err := NewDefault(ctx, option.DialerOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if d.networkStrategy != nil {
			t.Fatal("unexpected network strategy")
		}
	}
}

type unprotectedPlatform struct{ adapter.PlatformInterface }

func (*unprotectedPlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }

func TestFalseCapabilityPreservesAutoDetect(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "auto_false", true: "auto_true"}[auto], func(t *testing.T) {
			ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), &unprotectedPlatform{})
			ctx = service.ContextWith[adapter.NetworkManager](ctx, &protectionNetwork{auto: auto})
			d, err := NewDefault(ctx, option.DialerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if (d.networkStrategy != nil) != auto || d.defaultNetworkStrategy != auto {
				t.Fatal("false protection capability changed autodetect strategy")
			}
			// Bypass interface selection to exercise the constructed socket controls.
			conn, err := d.udpListener.ListenPacket(ctx, "udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
		})
	}
}

func TestRequiredProtectionMissingHook(t *testing.T) {
	for _, manager := range []adapter.NetworkManager{nil, &protectionNetwork{}} {
		ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), &protectionPlatform{})
		if manager != nil {
			ctx = service.ContextWith[adapter.NetworkManager](ctx, manager)
		}
		if _, err := NewDefault(ctx, option.DialerOptions{}); err == nil {
			t.Fatal("required protection missing: constructor succeeded")
		}
	}
}
