package hydra

// dpi-gate live integration (wave 3): the ClientSelfGate semantics from the
// Rust tunnel.rs run_rtc_pump, driven against the REAL Rust hydra-server on
// loopback:
//
//	Test A (no false positives): gate ON at the default threshold 0.5, clean
//	1 MB transfer — the own rtc wire must NEVER read as a tunnel: zero
//	rotate-requests, zero RotateMask polls, the tunnel stays alive and the
//	transfer is byte-exact.
//
//	Test B (rebuild action): threshold 0 (every full window reads as tunnel)
//	— the gate must raise, Poll must report RotateMask and Dead, and the
//	tunnel must die: exactly the Rust dead.store(true) -> rebuild trigger.
//
// The pump below mirrors rtc_tunnel.go's pump call-for-call (Receive /
// SendFrame / Poll under the rtcEngine mutex, 50 ms tick, Poll.Wire -> socket,
// Poll.Frames -> route) with the gate attached via SetDPIGate — the same seam
// the axes wiring attaches a catalogue candidate's gate through.
//
// Both tests skip when the hydra-server binary is absent (HYDRA_SERVER_BIN
// overrides; the default is the wave-3 target-dpigate build).

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const dpigateServerBin = "/home/varingait/src/hydra-adaptive/hydra/target-dpigate/release/hydra-server"

// startDpiGateServer spawns the wave-3 hydra-server with both listeners.
func startDpiGateServer(t *testing.T, keyPath string) (rtcAddr string, pubkey [32]byte, stop func()) {
	t.Helper()
	bin := os.Getenv("HYDRA_SERVER_BIN")
	if bin == "" {
		bin = dpigateServerBin
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("hydra-server binary not present (%s): %v", bin, err)
	}
	sk, err := decodeB64(string(mustRead(t, keyPath)))
	if err != nil || len(sk) != 32 {
		t.Fatalf("bad shared key file: %v", err)
	}
	pk, err := x25519Pub(sk)
	if err != nil {
		t.Fatal(err)
	}
	var kp [32]byte
	copy(kp[:], pk)

	wsAddr := net.JoinHostPort("127.0.0.1", fmt.Sprint(freePort(t)))
	rtcAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(freeUDPPort(t)))

	var stderr syncBuffer
	cmd := exec.Command(bin, keyPath, wsAddr)
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	cmd.Env = append(os.Environ(), "HYDRA_RTC_LISTEN="+rtcAddr)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("hydra-server stderr:\n%s", stderr.String())
		}
	})
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	stopped := false
	var mu sync.Mutex
	stop = func() {
		mu.Lock()
		defer mu.Unlock()
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
	t.Cleanup(stop)

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", wsAddr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hydra-server did not listen on %s; stderr:\n%s", wsAddr, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return rtcAddr, kp, stop
}

// dpiTestFlow is one rtc client flow with its pump: the rtc_tunnel.go call
// sequence with the dpi gate attached, plus rotate/death counters.
type dpiTestFlow struct {
	tun         *Tunnel
	eng         *rtcEngine
	pc          net.PacketConn
	udpAddr     *net.UDPAddr
	gate        *ClientSelfGate
	rotatePolls atomic.Uint64
	killed      atomic.Bool
}

// startDpiGateFlow dials the rtc transport, attaches gate, and runs the pump.
func startDpiGateFlow(t *testing.T, rtcAddr string, pubkey [32]byte, gate *ClientSelfGate) *dpiTestFlow {
	t.Helper()
	ap, err := netip.ParseAddrPort(rtcAddr)
	if err != nil {
		t.Fatal(err)
	}
	var staticPub [32]byte
	copy(staticPub[:], pubkey[:])

	ctx := t.Context()
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	tun := &Tunnel{
		raw:      &rtcRawConn{pc: pc},
		out:      make(chan []byte, chanSize),
		done:     make(chan struct{}),
		sessions: make(map[[IDSize]byte]*session),
		udp:      make(map[[IDSize]byte]*udpSession),
		negCh:    make(chan []byte, 4),
	}
	eng := &rtcEngine{engine: NewClient(staticPub, ap, time.Now())}
	eng.engine.SetDPIGate(gate)
	udpAddr := net.UDPAddrFromAddrPort(ap)
	flow := &dpiTestFlow{tun: tun, eng: eng, pc: pc, udpAddr: udpAddr, gate: gate}

	// recv: socket -> engine (rtc_tunnel.go's goroutine).
	go func() {
		pkt := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(pkt)
			if err != nil {
				tun.kill(err)
				return
			}
			eng.receive(pkt[:n], time.Now())
		}
	}()

	// pump: writes -> SendFrame; 50 ms tick -> Poll (rtc_tunnel.go's pump,
	// plus the RotateMask counter).
	go func() {
		ticker := time.NewTicker(rtcTickInterval)
		defer ticker.Stop()
		for {
			select {
			case <-tun.done:
				return
			case plain := <-tun.out:
				eng.send(plain)
			case now := <-ticker.C:
				poll := eng.poll(now)
				if poll.RotateMask {
					flow.rotatePolls.Add(1)
				}
				for _, dgram := range poll.Wire {
					if _, err := pc.WriteTo(dgram, udpAddr); err != nil {
						tun.kill(err)
						return
					}
				}
				for _, frame := range poll.Frames {
					tun.route(frame)
					if tun.IsDead() {
						return
					}
				}
				if poll.Dead {
					tun.kill(errRTCDead)
					return
				}
			}
		}
	}()

	// Wait for the masked handshake, like connectTunnelRTC.
	waitCtx, cancelWait := context.WithTimeout(ctx, rtcHandshakeTimeout)
	defer cancelWait()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-waitCtx.Done():
			tun.kill(waitCtx.Err())
			t.Fatalf("rtc handshake never came up: %v", waitCtx.Err())
		case <-tun.done:
			t.Fatalf("rtc tunnel died during handshake")
		case <-tick.C:
			if eng.connected() {
				return flow
			}
			if eng.isDead(time.Now()) {
				t.Fatalf("rtc engine dead during handshake")
			}
		}
	}
}

// raises / lastProb read gate diagnostics under the engine mutex — the pump
// goroutine mutates the gate inside poll, so raw reads would race.
func (f *dpiTestFlow) raises() uint64 {
	f.eng.mu.Lock()
	defer f.eng.mu.Unlock()
	return f.gate.raises
}

func (f *dpiTestFlow) lastProb() float32 {
	f.eng.mu.Lock()
	defer f.eng.mu.Unlock()
	return f.gate.lastProb
}

// dpiEchoTransfer pushes size bytes through the session to a TCP echo and
// verifies the response byte-exactly.
func dpiEchoTransfer(t *testing.T, s *session, size int) {
	t.Helper()
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := s.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 16384)
		read := 0
		for read < size {
			n, err := s.Read(buf)
			if err != nil {
				errCh <- fmt.Errorf("read at %d: %w", read, err)
				return
			}
			if !bytes.Equal(buf[:n], payload[read:read+n]) {
				errCh <- fmt.Errorf("byte mismatch at %d", read)
				return
			}
			read += n
		}
		errCh <- nil
	}()
	buf := make([]byte, 16384)
	written := 0
	for written < size {
		n := len(buf)
		if size-written < n {
			n = size - written
		}
		if _, err := s.Write(payload[written : written+n]); err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
	}
	if err := <-errCh; err != nil {
		t.Fatalf("echo transfer failed: %v", err)
	}
}

// TestDPIGateLiveCleanTransferNoRaise: gate ON, default threshold, real Rust
// server, clean 1 MB transfer — zero rotate-requests, tunnel alive.
func TestDPIGateLiveCleanTransferNoRaise(t *testing.T) {
	keyPath := writeSharedKey(t)
	rtcAddr, pubkey, _ := startDpiGateServer(t, keyPath)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	gate, err := EnableDPIGate(DPIGateDefaultThreshold)
	if err != nil {
		t.Fatalf("gate must enable on a parity-verified build: %v", err)
	}
	flow := startDpiGateFlow(t, rtcAddr, pubkey, gate)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	s, err := flow.tun.openSession(ctx, echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	dpiEchoTransfer(t, s, 1024*1024)
	_ = s.Close()

	if raises := flow.raises(); raises != 0 {
		t.Fatalf("clean transfer raised %d rotate-requests (false positives) — last p=%v",
			raises, flow.lastProb())
	}
	if n := flow.rotatePolls.Load(); n != 0 {
		t.Fatalf("clean transfer produced %d RotateMask polls", n)
	}
	if flow.tun.IsDead() {
		t.Fatal("clean transfer killed the tunnel")
	}
	if !flow.eng.connected() {
		t.Fatal("tunnel not connected after clean transfer")
	}
	t.Logf("clean 1MB transfer: %d raises, %d rotate polls, tunnel alive",
		flow.raises(), flow.rotatePolls.Load())
}

// TestDPIGateLiveRaiseKillsTunnel: threshold 0 makes every full window read
// as tunnel; the gate must raise, the poll must report RotateMask+Dead, and
// the tunnel must die (the rebuild action the adaptive layer reacts to).
func TestDPIGateLiveRaiseKillsTunnel(t *testing.T) {
	keyPath := writeSharedKey(t)
	rtcAddr, pubkey, _ := startDpiGateServer(t, keyPath)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	gate, err := EnableDPIGate(0) // every verdict > 0 raises
	if err != nil {
		t.Fatal(err)
	}
	gate = gate.WithStride(1) // judge every packet: raise as soon as the window fills
	flow := startDpiGateFlow(t, rtcAddr, pubkey, gate)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	s, err := flow.tun.openSession(ctx, echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	// Drive wire traffic until the gate raises and kills the tunnel.
	buf := make([]byte, 16384)
	deadline := time.Now().Add(30 * time.Second)
	for !flow.tun.IsDead() && time.Now().Before(deadline) {
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write(buf); err != nil {
			break // tunnel died under the write — expected once the gate raises
		}
	}

	if raises := flow.raises(); raises == 0 {
		t.Fatal("threshold-0 gate never raised — sampling hook is dead")
	}
	if n := flow.rotatePolls.Load(); n == 0 {
		t.Fatal("no poll reported RotateMask — the rebuild signal never fired")
	}
	if !flow.tun.IsDead() {
		t.Fatal("gate raise did not dead-flag the tunnel")
	}
	t.Logf("gate raised %d time(s) over %d poll(s); tunnel dead -> rebuild path",
		flow.raises(), flow.rotatePolls.Load())
}
