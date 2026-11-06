//go:build android

package hydra

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// newAdaptivePhysicalDialer binds a hydra adaptive candidate to the Android
// physical network. Android exposes no usable interface-name binding to
// apps, so the physical path is the platform-blessed one: a plain socket
// carrying the VPN service's ProtectFunc control hook, which makes its
// traffic bypass the tun and ride the carrier/Wi-Fi route. The seam mirrors
// common/dialer NewDefault: platform socket protection is independent of
// interface selection, and Android disables auto-detection but still
// requires protection.
//
// Fail-closed: every missing piece of the protection seam (platform
// interface, protection control, network manager, protect hook) is a typed
// error wrapping dialer.ErrPhysicalUnavailable — never a silent fallback
// dialer that would route candidate traffic back into the tun. The same
// applies to interface-name requests: on Android they cannot be honored, so
// they are rejected explicitly instead of silently ignored.
func newAdaptivePhysicalDialer(ctx context.Context, options *option.HydraAdaptiveOptions, candidate option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	if platformInterface == nil {
		return nil, fmt.Errorf("%w: android adaptive physical binding: platform interface missing", dialer.ErrPhysicalUnavailable)
	}
	if !platformInterface.UsePlatformAutoDetectInterfaceControl() {
		return nil, fmt.Errorf("%w: android adaptive physical binding: platform protection control disabled", dialer.ErrPhysicalUnavailable)
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, fmt.Errorf("%w: android adaptive physical binding: network manager missing", dialer.ErrPhysicalUnavailable)
	}
	protectFunc := networkManager.ProtectFunc()
	if protectFunc == nil {
		return nil, fmt.Errorf("%w: android adaptive physical binding: protection control hook missing", dialer.ErrPhysicalUnavailable)
	}
	if options != nil && options.PhysicalInterface != "" {
		return nil, fmt.Errorf("%w: android adaptive physical binding: group requests physical interface %q; named-interface binding is unavailable on Android, protected sockets carry the physical path", dialer.ErrPhysicalUnavailable, options.PhysicalInterface)
	}
	if candidate.BindInterface != "" {
		return nil, fmt.Errorf("%w: android adaptive physical binding: candidate %q requests bind interface %q; unavailable on Android", dialer.ErrPhysicalUnavailable, candidate.ID, candidate.BindInterface)
	}
	return &adaptivePhysicalAndroidDialer{
		dial:     net.Dialer{Control: control.Append(nil, protectFunc)},
		listener: net.ListenConfig{Control: control.Append(nil, protectFunc)},
	}, nil
}

// adaptivePhysicalAndroidDialer is a plain net dialer whose sockets are
// protected by the platform ProtectFunc. Domain candidates would resolve
// through the system resolver on sockets that carry no Control hook, so
// producers must use literal-IP endpoints on Android; IP endpoints need no
// resolution at all.
type adaptivePhysicalAndroidDialer struct {
	dial     net.Dialer
	listener net.ListenConfig
}

var _ N.Dialer = (*adaptivePhysicalAndroidDialer)(nil)

func (d *adaptivePhysicalAndroidDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsValid() {
		return nil, E.New("android physical dial: invalid destination")
	}
	return d.dial.DialContext(ctx, network, destination.String())
}

func (d *adaptivePhysicalAndroidDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.IsValid() {
		return nil, E.New("android physical dial: invalid destination")
	}
	network := N.NetworkUDP
	if destination.IsIPv4() && !destination.Addr.IsUnspecified() {
		network = N.NetworkUDP + "4"
	}
	return d.listener.ListenPacket(ctx, network, "")
}
