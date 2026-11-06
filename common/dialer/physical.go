package dialer

import (
	"errors"
	"net/netip"
)

// ErrPhysicalUnavailable means no verified physical path is available.
var ErrPhysicalUnavailable = errors.New("physical path unavailable")

// PhysicalOptions requires an explicit physical interface. Automatic selection is
// deliberately unsupported. DNS servers must be literal IP:port endpoints.
type PhysicalOptions struct {
	Interface  string
	DNSServers []netip.AddrPort
}
