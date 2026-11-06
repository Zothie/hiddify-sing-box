//go:build windows

package hydra

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func newAdaptivePhysicalDialer(ctx context.Context, options *option.HydraAdaptiveOptions, candidate option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
	servers := make([]netip.AddrPort, 0, len(options.PhysicalDNSServers))
	if len(options.PhysicalDNSServers) > 8 {
		return nil, fmt.Errorf("hydra: too many physical DNS endpoints")
	}
	for _, endpoint := range options.PhysicalDNSServers {
		server, err := netip.ParseAddrPort(endpoint)
		if err != nil || server.Port() == 0 {
			return nil, fmt.Errorf("hydra: physical DNS endpoint must be a literal IP:port")
		}
		servers = append(servers, server)
	}
	return dialer.NewPhysical(ctx, dialer.PhysicalOptions{Interface: options.PhysicalInterface, DNSServers: servers})
}
