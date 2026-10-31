package hydra

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	v2raywebsocket "github.com/sagernet/sing-box/transport/v2raywebsocket"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"

	"crypto/cipher"
)

// Timing constants mirror the Rust client (tunnel.rs).
const (
	// chanSize matches the Rust CHAN bound for session/udp/write channels.
	chanSize = 512
	// writeStallTimeout: a ws write blocked longer than this kills the tunnel
	// (Rust: tokio timeout on every sink.send).
	writeStallTimeout = 15 * time.Second
	// readerIdleTimeout: no message for this long kills the tunnel
	// (Rust: PING_EVERY + 5s around every rx.next()).
	readerIdleTimeout = 15 * time.Second
	// handshakeTimeout covers TCP+TLS+WS upgrade and the HELLO send
	// (Rust: CONNECT_TIMEOUT).
	handshakeTimeout = 8 * time.Second
	// replyTimeout covers the server REPLY and CONFIRM waits
	// (Rust: 10s each).
	replyTimeout = 10 * time.Second
	// openReplyTimeout is the OPEN -> OPEN-REPLY wait (Rust: 10s).
	openReplyTimeout = 10 * time.Second
)

// errTunnelReset is returned by sessions riding a dead tunnel.
var errTunnelReset = E.New("hydra: tunnel reset")

// DialFunc dials the transport TCP connection (TLS-wrapped when enabled).
type DialFunc func(ctx context.Context) (net.Conn, error)

// Tunnel is one multiplexed connection to a hydra server. Not safe for
// concurrent construction; all public methods are safe for use.
type Tunnel struct {
	raw  net.Conn // underlying (TLS) transport conn: deadline + abort handle
	ws   net.Conn // *v2raywebsocket.WebsocketConn, binary frames
	aead cipher.AEAD

	// ctr is the writer frame counter; CONFIRM consumed counter 1 on the
	// server side, so client data frames start at 1 (tunnel.rs wctr).
	ctr      atomic.Uint64
	out      chan []byte
	done     chan struct{}
	deadOnce sync.Once

	logger log.ContextLogger

	mu       sync.Mutex
	sessions map[[IDSize]byte]*session
	udp      map[[IDSize]byte]*udpSession
}

// IsDead reports whether the tunnel is dead and needs a rebuild.
func (t *Tunnel) IsDead() bool {
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}

// Done exposes the death signal for callers blocked on this tunnel.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Close kills the tunnel (idempotent).
func (t *Tunnel) Close() error {
	t.kill(nil)
	return nil
}

func (t *Tunnel) kill(cause error) {
	t.deadOnce.Do(func() {
		if cause != nil && t.logger != nil {
			t.logger.Trace("hydra tunnel died: ", cause)
		}
		close(t.done)
		// Unblocks the reader (read error) and any stalled write
		// (AfterFunc-based write stall uses the same path).
		t.raw.Close()
	})
}

// send enqueues one plaintext frame for the writer. The out channel is never
// closed, so callers select on done instead of relying on channel close.
func (t *Tunnel) send(plain []byte) bool {
	select {
	case t.out <- plain:
		return true
	case <-t.done:
		return false
	}
}

func (t *Tunnel) writerLoop() {
	for {
		select {
		case plain := <-t.out:
			ctr := t.ctr.Add(1) - 1
			frame := sealCtr(t.aead, ctr, plain)
			// WebsocketConn forbids deadlines (SetDeadline -> os.ErrInvalid),
			// so the 15s write-stall timeout is enforced by aborting the raw
			// transport conn, which unblocks the write with an error — the
			// same contract as Rust's timeout(15s, sink.send(...)).
			stall := time.AfterFunc(writeStallTimeout, func() { t.kill(E.New("hydra: write stall")) })
			_, err := t.ws.Write(frame)
			stall.Stop()
			if err != nil {
				t.kill(err)
				return
			}
		case <-t.done:
			return
		}
	}
}

func (t *Tunnel) readerLoop() {
	// Server CONFIRM was counter 1; server data frames start at 2
	// (tunnel.rs FrameStream::new(cipher, 2)).
	fs := newFrameStream(t.aead, 2)
	pkt := make([]byte, 65536)
	for {
		// Raw-conn read deadline: the only reliable idle watchdog (wrapper
		// deadlines are rejected; raw deadlines govern the underlying read).
		_ = t.raw.SetReadDeadline(time.Now().Add(readerIdleTimeout))
		n, err := t.ws.Read(pkt)
		if err != nil {
			t.kill(err)
			return
		}
		frames, err := fs.feed(pkt[:n])
		if err != nil {
			t.kill(err)
			return
		}
		for _, plain := range frames {
			t.route(plain)
			if t.IsDead() {
				return
			}
		}
	}
}

// route dispatches one decrypted server frame (tunnel.rs client_route_frame).
// Map lookups happen under the mutex but channel sends happen outside it, so
// one slow session cannot stall lookups for everyone.
func (t *Tunnel) route(plain []byte) {
	if len(plain) == 0 {
		return
	}
	switch plain[0] {
	case 3: // OPEN-REPLY [3][id16][ok] (optionally +[n][errmsg])
		if len(plain) < 18 {
			return
		}
		var id [IDSize]byte
		copy(id[:], plain[1:17])
		t.mu.Lock()
		s := t.sessions[id]
		t.mu.Unlock()
		if s == nil {
			return
		}
		ok := plain[17] == 1
		if !ok && len(plain) >= 19 {
			if n := int(plain[18]); len(plain) >= 19+n {
				s.openErr = string(plain[19 : 19+n])
			}
		}
		// Capacity 1, single sender (this goroutine); a timed-out opener must
		// not block the reader.
		select {
		case s.openCh <- ok:
		default:
		}
	case 2: // DATA [2][id16][bytes]
		if len(plain) < 17 {
			return
		}
		var id [IDSize]byte
		copy(id[:], plain[1:17])
		t.mu.Lock()
		s := t.sessions[id]
		t.mu.Unlock()
		if s == nil {
			return
		}
		// TCP data must not be dropped: block on the bounded channel like the
		// Rust reader does (backpressure reaches the whole tunnel).
		select {
		case s.data <- plain[17:]:
		case <-t.done:
		}
	case 4: // CLOSE [4][id16]
		if len(plain) < 17 {
			return
		}
		var id [IDSize]byte
		copy(id[:], plain[1:17])
		t.mu.Lock()
		s := t.sessions[id]
		delete(t.sessions, id)
		t.mu.Unlock()
		if s != nil {
			s.serverClosed()
		}
	case 6: // UDP-REPLY [6][id16][hlen][sip][sport][payload]
		if len(plain) < 22 {
			return
		}
		var id [IDSize]byte
		copy(id[:], plain[1:17])
		hl := int(plain[17])
		if len(plain) < 20+hl {
			return
		}
		sip := string(plain[18 : 18+hl])
		sport := binary.BigEndian.Uint16(plain[18+hl:])
		payload := plain[20+hl:]
		t.mu.Lock()
		u := t.udp[id]
		t.mu.Unlock()
		if u == nil {
			return
		}
		var addr net.Addr = badAddr{}
		if sa := M.ParseSocksaddrHostPort(sip, sport); sa.IsValid() {
			addr = sa
		}
		// UDP is lossy by nature: drop instead of stalling the tunnel.
		select {
		case u.data <- udpPacket{addr: addr, payload: payload}:
		default:
		}
	}
}

func (t *Tunnel) removeSession(id [IDSize]byte) {
	t.mu.Lock()
	delete(t.sessions, id)
	t.mu.Unlock()
}

func (t *Tunnel) removeUDP(id [IDSize]byte) {
	t.mu.Lock()
	delete(t.udp, id)
	t.mu.Unlock()
}

// badAddr is the placeholder source address for UDP-REPLYs whose sip does
// not parse (never happens with compliant servers).
type badAddr struct{}

func (badAddr) Network() string { return "hydra" }
func (badAddr) String() string  { return "hydra-unknown" }

// openSession sends OPEN and waits for the OPEN-REPLY (tunnel.rs open()).
func (t *Tunnel) openSession(ctx context.Context, host string, port uint16) (*session, error) {
	if host == "" || len(host) > 255 {
		return nil, E.New("hydra: invalid destination host")
	}
	var id [IDSize]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	s := newSession(t, id)
	t.mu.Lock()
	if t.IsDead() {
		t.mu.Unlock()
		return nil, errTunnelReset
	}
	t.sessions[id] = s
	t.mu.Unlock()

	frame := make([]byte, 0, 20+len(host))
	frame = append(frame, 0)
	frame = append(frame, id[:]...)
	frame = append(frame, byte(len(host)))
	frame = append(frame, host...)
	frame = binary.BigEndian.AppendUint16(frame, port)
	if !t.send(frame) {
		t.removeSession(id)
		return nil, errTunnelReset
	}
	select {
	case ok := <-s.openCh:
		if !ok {
			t.removeSession(id)
			msg := s.openErr
			if msg == "" {
				return nil, E.New("hydra: remote open failed")
			}
			return nil, E.New("hydra: remote open failed: ", msg)
		}
		return s, nil
	case <-time.After(openReplyTimeout):
		t.removeSession(id)
		return nil, E.New("hydra: open timeout")
	case <-ctx.Done():
		t.removeSession(id)
		return nil, ctx.Err()
	case <-t.done:
		t.removeSession(id)
		return nil, errTunnelReset
	}
}

// openUDP registers a fresh UDP session id for a PacketConn.
func (t *Tunnel) openUDP() *udpSession {
	var id [IDSize]byte
	_, _ = rand.Read(id[:])
	u := newUDPSession(t, id)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.IsDead() {
		t.udp[id] = u
		return u
	}
	// Tunnel died between getTunnel and registration: still return a working
	// object; its first WriteTo will fail with errTunnelReset.
	u.dead = true
	return u
}

// connectTunnel performs dial + WS upgrade + the hydra handshake and starts
// the reader/writer pumps. dial must return the (TLS-wrapped) transport conn;
// requestURL carries scheme (ws/wss), Host header and path.
func connectTunnel(ctx context.Context, dial DialFunc, requestURL *url.URL, headers http.Header, serverStatic []byte, logger log.ContextLogger) (*Tunnel, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	raw, err := dial(ctx)
	if err != nil {
		return nil, E.Cause(err, "hydra: transport dial")
	}
	conn := raw
	// The HTTP upgrade itself has no ctx path (it reads/writes the raw conn),
	// so a stalled 101 response is bounded by a raw-conn deadline — without it
	// getTunnel (holding the rebuild mutex) would wedge on a silent peer.
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	reader, _, err := ws.Dialer{Header: ws.HandshakeHeaderHTTP(headers)}.Upgrade(conn, requestURL)
	if err != nil {
		raw.Close()
		return nil, E.Cause(err, "hydra: websocket upgrade")
	}
	_ = raw.SetDeadline(time.Time{})
	if reader != nil && reader.Buffered() > 0 {
		// Response bytes arrived piggybacked on the handshake; keep them.
		buffer := buf.NewSize(reader.Buffered())
		_, err = buffer.ReadFullFrom(reader, buffer.Len())
		if err != nil {
			raw.Close()
			return nil, E.Cause(err, "hydra: websocket upgrade")
		}
		conn = bufio.NewCachedConn(conn, buffer)
	}
	wsConn := v2raywebsocket.NewConn(conn, nil, ws.StateClientSide)

	fail := func(err error) (*Tunnel, error) {
		raw.Close()
		return nil, err
	}

	// eph keypair + salt
	ephSk := make([]byte, 32)
	if _, err = rand.Read(ephSk); err != nil {
		return fail(err)
	}
	ephPub, err := x25519Pub(ephSk)
	if err != nil {
		return fail(err)
	}
	salt := make([]byte, SaltSize)
	if _, err = rand.Read(salt); err != nil {
		return fail(err)
	}
	helloCipher, err := kdfHello(serverStatic, salt)
	if err != nil {
		return fail(err)
	}

	// HELLO: [u32 len][salt16][seal(kdf_hello, ctr 0, MAGIC || eph_pub)]
	inner := make([]byte, 0, len(Magic)+32)
	inner = append(inner, Magic[:]...)
	inner = append(inner, ephPub...)
	hello := salt
	hello = append(hello, sealCtr(helloCipher, 0, inner)...)
	helloFrame := binary.BigEndian.AppendUint32(nil, uint32(len(hello)))
	helloFrame = append(helloFrame, hello...)

	_ = raw.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	if _, err = wsConn.Write(helloFrame); err != nil {
		return fail(E.Cause(err, "hydra: hello send"))
	}
	_ = raw.SetWriteDeadline(time.Time{})

	// REPLY: [u32 len][MAGIC || spice_pub || salt]
	readBuf := make([]byte, 65536)
	_ = raw.SetReadDeadline(time.Now().Add(replyTimeout))
	n, err := wsConn.Read(readBuf)
	if err != nil {
		return fail(E.Cause(err, "hydra: reply read"))
	}
	reply := readBuf[:n]
	if len(reply) >= 57 && bytes.Equal(reply[4:9], Magic[:]) {
		reply = reply[4:]
	}
	if len(reply) < 53 || !bytes.Equal(reply[:5], Magic[:]) {
		return fail(E.New("hydra: bad reply"))
	}
	spice := reply[5:37]

	sharedEph, err := x25519(ephSk, spice)
	if err != nil {
		return fail(E.New("hydra: ecdh failed"))
	}
	sharedStatic, err := x25519(ephSk, serverStatic)
	if err != nil {
		return fail(E.New("hydra: ecdh failed"))
	}
	transcript := make([]byte, 0, 64)
	transcript = append(transcript, ephPub...)
	transcript = append(transcript, spice...)
	cipher, err := kdfAuth(sharedEph, sharedStatic, salt, transcript)
	if err != nil {
		return fail(err)
	}

	// CONFIRM at counter 1
	_ = raw.SetReadDeadline(time.Now().Add(replyTimeout))
	n, err = wsConn.Read(readBuf)
	if err != nil {
		return fail(E.Cause(err, "hydra: confirm read"))
	}
	confirm, err := openCtr(cipher, 1, readBuf[:n])
	if err != nil || !constantTimeEquals(confirm, []byte("hydra-confirm")) {
		return fail(E.New("hydra: server authentication failed (MITM or wrong pubkey)"))
	}
	_ = raw.SetReadDeadline(time.Time{})

	tunnel := &Tunnel{
		raw:      raw,
		ws:       wsConn,
		aead:     cipher,
		out:      make(chan []byte, chanSize),
		done:     make(chan struct{}),
		logger:   logger,
		sessions: make(map[[IDSize]byte]*session),
		udp:      make(map[[IDSize]byte]*udpSession),
	}
	tunnel.ctr.Store(1) // client data frames start at 1
	go tunnel.writerLoop()
	go tunnel.readerLoop()
	return tunnel, nil
}

// buildTLSConfigAndDialer builds the optional TLS fronting dialer.
func buildTLSConfigAndDialer(ctx context.Context, logger log.ContextLogger, baseDialer N.Dialer, serverAddr M.Socksaddr, tlsOptions *option.OutboundTLSOptions) (N.Dialer, error) {
	if tlsOptions == nil || !tlsOptions.Enabled {
		return baseDialer, nil
	}
	// Mirror the Rust client: rustls is pinned to TLS 1.3 and certificate
	// verification is always skipped. Server authentication is the
	// pubkey-bound CONFIRM frame, so TLS is pure camouflage.
	tlsOptions.Insecure = true
	if tlsOptions.MinVersion == "" {
		tlsOptions.MinVersion = "1.3"
	}
	if tlsOptions.MaxVersion == "" {
		tlsOptions.MaxVersion = "1.3"
	}
	tlsConfig, err := tls.NewClient(ctx, logger, serverAddr.AddrString(), *tlsOptions)
	if err != nil {
		return nil, E.Cause(err, "create TLS config")
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{"http/1.1"})
	}
	return tls.NewDialer(baseDialer, tlsConfig), nil
}
