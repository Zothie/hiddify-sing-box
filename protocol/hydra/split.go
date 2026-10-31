package hydra

import (
	"context"
	"math/rand"
	"net"
	"sync"

	N "github.com/sagernet/sing/common/network"
	M "github.com/sagernet/sing/common/metadata"
)

// ClientHello fragment sizes (NoDPI-style, mirrors the Rust client's frag.rs):
// the first TCP segment of the TLS record carries 8-64 bytes (cutting at or
// inside the SNI), the rest are sent in <=96-byte pieces. crypto/tls emits the
// whole ClientHello record in one Write, so splitting at the conn level splits
// the record on the wire.
const (
	splitFirstMin = 8
	splitFirstMax = 64
	splitRestMax  = 96
)

// helloSplitConn fragments the FIRST Write on the underlying TLS connection.
// Later writes pass through untouched.
type helloSplitConn struct {
	net.Conn
	mu    sync.Mutex
	first bool
}

func newHelloSplitConn(c net.Conn) *helloSplitConn {
	return &helloSplitConn{Conn: c, first: true}
}

func (c *helloSplitConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	isFirst := c.first
	if isFirst {
		c.first = false
	}
	c.mu.Unlock()
	if !isFirst {
		return c.Conn.Write(b)
	}
	first := splitFirstMin + rand.Intn(splitFirstMax-splitFirstMin+1)
	if first > len(b) {
		first = len(b)
	}
	written := 0
	for written < len(b) {
		take := len(b) - written
		if written == 0 {
			take = min(take, first)
		} else {
			take = min(take, splitRestMax)
		}
		if _, err := c.Conn.Write(b[written : written+take]); err != nil {
			return written, err
		}
		written += take
	}
	return len(b), nil
}

// splitDialer wraps a TLS dialer so every produced connection fragments its
// first record.
type splitDialer struct {
	N.Dialer
}

func (d splitDialer) DialContext(ctx context.Context, network string,
	destination M.Socksaddr) (net.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return newHelloSplitConn(c), nil
}
