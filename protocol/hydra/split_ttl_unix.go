//go:build unix

package hydra

import "syscall"

// Socket-level half of the disorder trick (split.go ttlDisorderConn): read
// and write the IP hop limit of the BASE TCP socket below TLS. v6 uses
// IPV6_UNICAST_HOPS, everything else IP_TTL.

func ttlSockOpts(v6 bool) (int, int) {
	if v6 {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func sockReadTTL(fd uintptr, v6 bool) (int, error) {
	level, opt := ttlSockOpts(v6)
	return syscall.GetsockoptInt(int(fd), level, opt)
}

func sockWriteTTL(fd uintptr, v6 bool, value int) error {
	level, opt := ttlSockOpts(v6)
	return syscall.SetsockoptInt(int(fd), level, opt, value)
}
