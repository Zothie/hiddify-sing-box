//go:build !linux && !windows && !android

package dialer

import (
	"context"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
)

type PhysicalDialer struct{}

var _ N.Dialer = (*PhysicalDialer)(nil)

func physicalUnavailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrPhysicalUnavailable
}

func NewPhysical(ctx context.Context, options PhysicalOptions) (*PhysicalDialer, error) {
	return nil, physicalUnavailable(ctx)
}
func (d *PhysicalDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return nil, physicalUnavailable(ctx)
}
func (d *PhysicalDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, physicalUnavailable(ctx)
}
