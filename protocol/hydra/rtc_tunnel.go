package hydra

// rtc:// transport: one UDP socket + the RtcMask client engine + the standard
// Tunnel session layer. The engine (rtc.go) owns masking, the reliable data
// plane and keepalives (RTCP-SR + ICE consent every 5 s); this file owns only
// the socket pump glue:
//
//	socket → engine.Receive(packet, now)
//	ticker 50 ms (Rust RTC_TICK) → engine.Poll(now):
//	    Poll.Wire datagrams → socket,
//	    Poll.Frames         → the same plaintext routing the ws Tunnel uses
//	Tunnel.out (session writes, negotiate offer) → engine.SendFrame
//
// The returned *Tunnel is a regular adaptive Resource: openSession, openUDP,
// negotiation and tunnel proof work unchanged — only writerLoop/readerLoop
// are replaced by the pump below. Tunnel.kill closes the socket (through the
// rtcRawConn face), which unblocks the recv goroutine; engine dead/timeout
// (12 s handshake, 30 s idle per Rust semantics) kills the tunnel from the
// pump. Context cancellation closes the socket until the handshake lands.

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

// rtcTickInterval mirrors the Rust RTC_TICK (rtc.rs): one Poll per tick per
// flow. Every tunnel drives its own goroutine — no global ticker.
const rtcTickInterval = 50 * time.Millisecond

// errRTCDead reports the engine's terminal state (handshake timeout or idle
// without verified inbound traffic, both enforced by the engine's IsDead).
var errRTCDead = E.New("hydra: rtc engine dead (handshake timeout or idle)")

// rtcPacketDial returns the UDP socket for one rtc flow. N.Dialer.ListenPacket
// (including PhysicalDialer, which binds the physical interface) provides it.
type rtcPacketDial func(ctx context.Context) (net.PacketConn, error)

// rtcRawConn adapts the UDP PacketConn to the net.Conn the Tunnel kill path
// closes. The net.Conn face is never read or written: the pump owns all
// socket I/O through the PacketConn.
type rtcRawConn struct{ pc net.PacketConn }

func (c *rtcRawConn) Read(b []byte) (int, error)         { return 0, net.ErrClosed }
func (c *rtcRawConn) Write(b []byte) (int, error)        { return 0, net.ErrClosed }
func (c *rtcRawConn) Close() error                       { return c.pc.Close() }
func (c *rtcRawConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *rtcRawConn) RemoteAddr() net.Addr               { return nil }
func (c *rtcRawConn) SetDeadline(t time.Time) error      { return nil }
func (c *rtcRawConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *rtcRawConn) SetWriteDeadline(t time.Time) error { return nil }

// rtcEngine serializes the engine between the recv and pump goroutines. The
// RtcMask is synchronous and deliberately unshared, so all Receive/SendFrame/
// Poll accesses take the lock; the pump is the only clock driver.
type rtcEngine struct {
	mu     sync.Mutex
	engine *RtcMask
}

func (e *rtcEngine) receive(pkt []byte, now time.Time) {
	e.mu.Lock()
	e.engine.Receive(pkt, now)
	e.mu.Unlock()
}

func (e *rtcEngine) send(plain []byte) {
	e.mu.Lock()
	e.engine.SendFrame(plain)
	e.mu.Unlock()
}

func (e *rtcEngine) poll(now time.Time) RtcPoll {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.engine.Poll(now)
}

func (e *rtcEngine) connected() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.engine.Connected()
}

func (e *rtcEngine) isDead(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.engine.IsDead(now)
}

// connectTunnelRTC is the rtc:// twin of connectTunnel. peer is the server's
// UDP address; serverStatic is the server static pubkey (the same trust
// anchor as the ws handshake — the CONFIRM frame binds it). Optional axes
// carry the candidate's rtc engine tuning (chunk/window/rto/buffer/keepalive/
// pad); zero axes keep the engine defaults.
func connectTunnelRTC(ctx context.Context, packetDial rtcPacketDial, serverStatic []byte, peer netip.AddrPort, logger log.ContextLogger, negotiateMaxFrame uint32, axes ...tunnelAxes) (*Tunnel, error) {
	var staticPub [32]byte
	copy(staticPub[:], serverStatic)

	dialCtx, cancelDial := context.WithTimeout(ctx, handshakeTimeout)
	defer cancelDial()
	pc, err := packetDial(dialCtx)
	if err != nil {
		return nil, E.Cause(err, "hydra: rtc transport dial")
	}

	tunnel := &Tunnel{
		raw:      &rtcRawConn{pc: pc}, // kill() closes the socket through this
		out:      make(chan []byte, chanSize),
		done:     make(chan struct{}),
		logger:   logger,
		sessions: make(map[[IDSize]byte]*session),
		udp:      make(map[[IDSize]byte]*udpSession),
		negCh:    make(chan []byte, 4),
	}

	// ctx cancellation closes the socket until the handshake lands; after
	// handover the tunnel lives on its own clocks, exactly like the ws path.
	stopCancellation := context.AfterFunc(ctx, func() { tunnel.kill(ctx.Err()) })

	ax := firstTunnelAxes(axes)
	engine := NewClientWithParams(staticPub, peer, time.Now(), rtcChannelParams(ax))
	// DPI self-gate (rtc pump only): attached BEFORE the pump starts, so the
	// very first poll samples it. FAIL-TO-OFF is intentional — the gate can
	// only fail on the embedded model digest check, and a gateless tunnel
	// beats no tunnel; never fail the dial for a camouflage knob.
	if ax.dpiGateEnabled {
		gate, gerr := EnableDPIGate(ax.dpiGateThreshold)
		if gerr != nil {
			if logger != nil {
				logger.Warn("hydra: dpi gate disabled (fail-to-off): ", gerr)
			}
		} else {
			engine.SetDPIGate(gate)
		}
	}
	eng := &rtcEngine{engine: engine}
	udpAddr := net.UDPAddrFromAddrPort(peer)

	// recv: socket → engine. kill() closes the socket, which unblocks this
	// loop; its trailing kill is then a no-op (deadOnce).
	go func() {
		pkt := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(pkt)
			if err != nil {
				tunnel.kill(err)
				return
			}
			eng.receive(pkt[:n], time.Now())
		}
	}()

	// pump: 50 ms tick → Poll; session writes → SendFrame; decrypted frames →
	// the standard Tunnel routing.
	go func() {
		ticker := time.NewTicker(rtcTickInterval)
		defer ticker.Stop()
		for {
			select {
			case <-tunnel.done:
				return
			case plain := <-tunnel.out:
				eng.send(plain)
			case now := <-ticker.C:
				poll := eng.poll(now)
				for _, dgram := range poll.Wire {
					if _, err := pc.WriteTo(dgram, udpAddr); err != nil {
						tunnel.kill(E.Cause(err, "hydra: rtc write"))
						return
					}
				}
				for _, frame := range poll.Frames {
					tunnel.route(frame)
					if tunnel.IsDead() {
						return
					}
				}
				if poll.Dead {
					tunnel.kill(errRTCDead)
					return
				}
			}
		}
	}()

	// Wait for the masked handshake (HELLO → STUN reply → CONFIRM). The bound
	// matches the engine's own handshake timeout.
	waitCtx, cancelWait := context.WithTimeout(ctx, rtcHandshakeTimeout)
	defer cancelWait()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-waitCtx.Done():
			tunnel.kill(waitCtx.Err())
			return nil, waitCtx.Err()
		case <-tunnel.done:
			return nil, errRTCDead
		case <-tick.C:
			now := time.Now()
			if eng.connected() {
				if !stopCancellation() || ctx.Err() != nil {
					tunnel.kill(ctx.Err())
					return nil, ctx.Err()
				}
				if negotiateMaxFrame != 0 {
					// Same negotiation as ws (frame types 8/9/10): the offer
					// rides the rtc data plane like any session frame; the
					// ACCEPT/REPLY frames come back through Poll.Frames.
					tunnel.negotiate(buildNegotiate(negotiateMaxFrame), logger)
				}
				return tunnel, nil
			}
			if eng.isDead(now) {
				tunnel.kill(errRTCDead)
				return nil, errRTCDead
			}
		}
	}
}
