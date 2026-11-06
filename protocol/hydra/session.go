package hydra

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// session is one multiplexed TCP stream over the tunnel, exposed as net.Conn.
//
// Channel discipline (from the concurrency audit):
//   - s.data is sent to ONLY by the tunnel reader goroutine and is never
//     closed; EOF is signaled via eofCh, which only the reader closes.
//   - closedCh is closed once by local Close (sync.Once) — the only other
//     closer-free channel; Read/Write select on both.
//   - therefore no "send on closed channel" and no double-close is possible.
type session struct {
	tun *Tunnel
	id  [IDSize]byte

	data    chan []byte
	openCh  chan bool
	openErr string // written by the reader before openCh send; read after receive

	pending []byte // remainder of a payload too big for the caller's buffer

	closeOnce      sync.Once
	closeWriteOnce sync.Once
	eofOnce        sync.Once

	closedCh chan struct{} // local Close
	eofCh    chan struct{} // server [4] CLOSE

	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
}

func newSession(tun *Tunnel, id [IDSize]byte) *session {
	return &session{
		tun:      tun,
		id:       id,
		data:     make(chan []byte, chanSize),
		openCh:   make(chan bool, 1),
		closedCh: make(chan struct{}),
		eofCh:    make(chan struct{}),
	}
}

// serverClosed marks remote EOF (server sent CLOSE).
func (s *session) serverClosed() {
	s.eofOnce.Do(func() { close(s.eofCh) })
}

func deadlineChan(v int64) <-chan time.Time {
	if v == 0 {
		return nil
	}
	d := time.Unix(0, v)
	if time.Now().After(d) {
		return time.After(0)
	}
	return time.After(time.Until(d))
}

func (s *session) Read(b []byte) (int, error) {
	for {
		if len(s.pending) > 0 {
			n := copy(b, s.pending)
			s.pending = s.pending[n:]
			if len(s.pending) == 0 {
				s.pending = nil
			}
			return n, nil
		}
		var deadline <-chan time.Time
		if v := s.readDeadline.Load(); v != 0 {
			deadline = deadlineChan(v)
		}
		select {
		case payload := <-s.data:
			n := copy(b, payload)
			if n < len(payload) {
				s.pending = payload[n:]
			}
			return n, nil
		case <-s.eofCh:
			// Prefer buffered data before reporting EOF (no data loss when
			// CLOSE [4] races the last DATA frames).
			select {
			case payload := <-s.data:
				n := copy(b, payload)
				if n < len(payload) {
					s.pending = payload[n:]
				}
				return n, nil
			default:
				return 0, io.EOF
			}
		case <-s.closedCh:
			return 0, net.ErrClosed
		case <-s.tun.done:
			return 0, errTunnelReset
		case <-deadline:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (s *session) Write(b []byte) (int, error) {
	select {
	case <-s.closedCh:
		return 0, net.ErrClosed
	case <-s.tun.done:
		return 0, errTunnelReset
	default:
	}
	if len(b) == 0 {
		return 0, nil
	}
	var deadline <-chan time.Time
	if v := s.writeDeadline.Load(); v != 0 {
		deadline = deadlineChan(v)
	}
	frame := make([]byte, 0, 1+IDSize+len(b))
	frame = append(frame, 2)
	frame = append(frame, s.id[:]...)
	frame = append(frame, b...)
	select {
	case s.tun.out <- frame:
		return len(b), nil
	case <-s.tun.done:
		return 0, errTunnelReset
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	}
}

// Close sends CLOSE [1][id] and deregisters (tunnel.rs pump_pair tail). Safe
// to call repeatedly and after CloseWrite.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		close(s.closedCh)
		s.tun.removeSession(s.id)
		frame := make([]byte, 0, 1+IDSize)
		frame = append(frame, 1)
		frame = append(frame, s.id[:]...)
		select {
		case s.tun.out <- frame:
		default:
			// Local cleanup must not wait on a stalled shared tunnel.
		}
	})
	return nil
}

// CloseWrite sends HALF-CLOSE [7][id] (client done writing; the server
// shuts down its side of the upstream connection).
func (s *session) CloseWrite() error {
	s.closeWriteOnce.Do(func() {
		frame := make([]byte, 0, 1+IDSize)
		frame = append(frame, 7)
		frame = append(frame, s.id[:]...)
		s.tun.send(frame)
	})
	return nil
}

func (s *session) LocalAddr() net.Addr  { return s.tun.raw.LocalAddr() }
func (s *session) RemoteAddr() net.Addr { return s.tun.raw.RemoteAddr() }

func (s *session) SetDeadline(t time.Time) error {
	s.readDeadline.Store(t.UnixNano())
	s.writeDeadline.Store(t.UnixNano())
	return nil
}

func (s *session) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(t.UnixNano())
	return nil
}

func (s *session) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(t.UnixNano())
	return nil
}

// udpPacket carries one UDP-REPLY payload with its parsed source address.
type udpPacket struct {
	addr    net.Addr
	payload []byte
}

// socksaddrHost extracts the wire host string, unwrapping IPv4-mapped
// IPv6 (::ffff:a.b.c.d) so the Rust server receives a clean IPv4 literal.
func socksaddrHost(sa M.Socksaddr) string {
	if sa.IsIP() && sa.Addr.Is4In6() {
		return sa.Addr.Unmap().String()
	}
	return sa.AddrString()
}

// udpSession is one hydra UDP session (server keeps one relay socket per
// session id), exposed as net.PacketConn.
type udpSession struct {
	tun *Tunnel
	id  [IDSize]byte

	data      chan udpPacket
	closedCh  chan struct{}
	closeOnce sync.Once
	dead      bool // tunnel died before registration

	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
}

func newUDPSession(tun *Tunnel, id [IDSize]byte) *udpSession {
	return &udpSession{
		tun:      tun,
		id:       id,
		data:     make(chan udpPacket, chanSize),
		closedCh: make(chan struct{}),
	}
}

func (u *udpSession) ReadFrom(b []byte) (int, net.Addr, error) {
	var deadline <-chan time.Time
	if v := u.readDeadline.Load(); v != 0 {
		deadline = deadlineChan(v)
	}
	select {
	case pkt := <-u.data:
		n := copy(b, pkt.payload)
		return n, pkt.addr, nil
	case <-u.closedCh:
		return 0, nil, net.ErrClosed
	case <-u.tun.done:
		return 0, nil, errTunnelReset
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (u *udpSession) WriteTo(b []byte, addr net.Addr) (int, error) {
	if u.dead {
		return 0, errTunnelReset
	}
	select {
	case <-u.closedCh:
		return 0, net.ErrClosed
	case <-u.tun.done:
		return 0, errTunnelReset
	default:
	}
	// UDP-DATA [5][id16][hlen][host][port][payload]
	sa := M.SocksaddrFromNet(addr)
	if !sa.IsValid() {
		return 0, E.New("hydra: invalid UDP destination")
	}
	host := socksaddrHost(sa)
	port := sa.Port
	if host == "" || len(host) > 255 {
		return 0, E.New("hydra: invalid UDP destination")
	}
	var deadline <-chan time.Time
	if v := u.writeDeadline.Load(); v != 0 {
		deadline = deadlineChan(v)
	}
	frame := make([]byte, 0, 20+len(host)+len(b))
	frame = append(frame, 5)
	frame = append(frame, u.id[:]...)
	frame = append(frame, byte(len(host)))
	frame = append(frame, host...)
	frame = binary.BigEndian.AppendUint16(frame, port)
	frame = append(frame, b...)
	select {
	case u.tun.out <- frame:
		return len(b), nil
	case <-u.tun.done:
		return 0, errTunnelReset
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	}
}

// Close deregisters the UDP session server-side via CLOSE [1] (dispatch
// removes the relay entry) and drops the local mapping. Idempotent.
func (u *udpSession) Close() error {
	u.closeOnce.Do(func() {
		close(u.closedCh)
		u.tun.removeUDP(u.id)
		frame := make([]byte, 0, 1+IDSize)
		frame = append(frame, 1)
		frame = append(frame, u.id[:]...)
		select {
		case u.tun.out <- frame:
		default:
			// Local cleanup must not wait on a stalled shared tunnel.
		}
	})
	return nil
}

func (u *udpSession) LocalAddr() net.Addr { return u.tun.raw.LocalAddr() }

func (u *udpSession) SetDeadline(t time.Time) error {
	u.readDeadline.Store(t.UnixNano())
	u.writeDeadline.Store(t.UnixNano())
	return nil
}

func (u *udpSession) SetReadDeadline(t time.Time) error {
	u.readDeadline.Store(t.UnixNano())
	return nil
}

func (u *udpSession) SetWriteDeadline(t time.Time) error {
	u.writeDeadline.Store(t.UnixNano())
	return nil
}
