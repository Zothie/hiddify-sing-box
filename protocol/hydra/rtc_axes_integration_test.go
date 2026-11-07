package hydra

// RTC axes integration: the Go client with per-candidate engine params
// (RtcChannelParams) against the REAL Rust hydra-server started with matched
// HYDRA_RTC_CHUNK / HYDRA_RTC_WINDOW env values.
//
// Per variant (own key, own server instance, own env — independent knob sets):
//   1. handshake + CONFIRM complete,
//   2. the useful proof passes (64 KiB SHA256-chained nonce body through the
//      tunnel — at any clamped chunk this is far more than 4 data packets),
//   3. a direct 32 KiB TCP echo roundtrip through a tunnel session is
//      byte-exact (>4 chunks in both directions),
//   4. the wire histogram shows the SERVER actually chunked at its env value
//      (full data bodies of exactly 4+chunk bytes) — the knob is live, and a
//      second variant with different values passes against its own server.
//
// Coupling (audit F5): matched values are CATALOGUE POLICY (server env must
// match), not a protocol requirement — the receiver is length-agnostic, so
// there is deliberately no must-fail negative test.
//
// Skipped when the binary is absent (HYDRA_SERVER_BIN overrides; the default
// points at the hydra-adaptive debug build, the one with rtc).
//
// connectTunnelRTCParams mirrors the rtc_tunnel.go pump glue byte-for-byte
// except that the engine is constructed with NewClientWithParams (production
// wiring threads params through rtc_tunnel.go; the test must not edit a file
// it does not own).

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

// startRustServerRTCEnv spawns hydra-server like startRustServerRTC, plus
// extra env entries (the RTC axis knobs).
func startRustServerRTCEnv(t *testing.T, keyPath string, extraEnv ...string) (wsAddr string, rtcAddr string, pubkey [32]byte, stop func()) {
	t.Helper()
	bin := os.Getenv("HYDRA_SERVER_BIN")
	if bin == "" {
		bin = defaultRTCServerBin
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

	wsAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(freePort(t)))
	rtcAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(freeUDPPort(t)))

	var stderr syncBuffer
	cmd := exec.Command(bin, keyPath, wsAddr)
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	cmd.Env = append(os.Environ(), "HYDRA_DEBUG=1", "HYDRA_RTC_LISTEN="+rtcAddr)
	cmd.Env = append(cmd.Env, extraEnv...)
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
	return wsAddr, rtcAddr, kp, stop
}

// axisEngine is the rtcEngine pump wrapper plus a wire histogram: it counts
// authenticated data bodies received FROM the server by length, so the test
// can observe the server's actual chunking.
type axisEngine struct {
	mu     sync.Mutex
	engine *RtcMask
	histo  map[int]int
}

func (e *axisEngine) receive(pkt []byte, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.engine.Receive(pkt, now)
	if e.engine.rtcCipher == nil || len(pkt) < RTPHeaderLen+NonceSize+16 || pkt[0]&0xc0 != 0x80 || pkt[1]&0x7f != RTPPtOpus {
		return
	}
	if ctr, body, ok := openMask(e.engine.rtcCipher, pkt[RTPHeaderLen:]); ok &&
		ctr >= dataCounterBase && ctr < parityCounterBase {
		e.histo[len(body)]++
	}
}

func (e *axisEngine) send(plain []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.engine.SendFrame(plain)
}

func (e *axisEngine) poll(now time.Time) RtcPoll {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.engine.Poll(now)
}

func (e *axisEngine) connected() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.engine.Connected()
}

func (e *axisEngine) isDead(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.engine.IsDead(now)
}

func (e *axisEngine) snapshot() map[int]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[int]int, len(e.histo))
	for k, v := range e.histo {
		out[k] = v
	}
	return out
}

// connectTunnelRTCParams is connectTunnelRTC (rtc_tunnel.go) with the engine
// params threaded through NewClientWithParams; it returns the histogram probe.
func connectTunnelRTCParams(ctx context.Context, packetDial func(context.Context) (net.PacketConn, error), serverStatic []byte, peer netip.AddrPort, logger log.ContextLogger, negotiateMaxFrame uint32, params RtcChannelParams) (*Tunnel, *axisEngine, error) {
	var staticPub [32]byte
	copy(staticPub[:], serverStatic)

	dialCtx, cancelDial := context.WithTimeout(ctx, handshakeTimeout)
	defer cancelDial()
	pc, err := packetDial(dialCtx)
	if err != nil {
		return nil, nil, err
	}

	tunnel := &Tunnel{
		raw:      &rtcRawConn{pc: pc},
		out:      make(chan []byte, chanSize),
		done:     make(chan struct{}),
		logger:   logger,
		sessions: make(map[[IDSize]byte]*session),
		udp:      make(map[[IDSize]byte]*udpSession),
		negCh:    make(chan []byte, 4),
	}
	stopCancellation := context.AfterFunc(ctx, func() { tunnel.kill(ctx.Err()) })

	eng := &axisEngine{engine: NewClientWithParams(staticPub, peer, time.Now(), params), histo: make(map[int]int)}
	udpAddr := net.UDPAddrFromAddrPort(peer)

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
						tunnel.kill(err)
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

	waitCtx, cancelWait := context.WithTimeout(ctx, rtcHandshakeTimeout)
	defer cancelWait()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-waitCtx.Done():
			tunnel.kill(waitCtx.Err())
			return nil, nil, waitCtx.Err()
		case <-tunnel.done:
			return nil, nil, errRTCDead
		case <-tick.C:
			now := time.Now()
			if eng.connected() {
				if !stopCancellation() || ctx.Err() != nil {
					tunnel.kill(ctx.Err())
					return nil, nil, ctx.Err()
				}
				if negotiateMaxFrame != 0 {
					tunnel.negotiate(buildNegotiate(negotiateMaxFrame), logger)
				}
				return tunnel, eng, nil
			}
			if eng.isDead(now) {
				tunnel.kill(errRTCDead)
				return nil, nil, errRTCDead
			}
		}
	}
}

func dialRTCTunnelWithParams(t *testing.T, rtcAddr string, pubkey [32]byte, params RtcChannelParams) (*Tunnel, *axisEngine) {
	t.Helper()
	ap, err := netip.ParseAddrPort(rtcAddr)
	if err != nil {
		t.Fatal(err)
	}
	var lastErr error
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		tun, eng, err := connectTunnelRTCParams(t.Context(), func(ctx context.Context) (net.PacketConn, error) {
			var lc net.ListenConfig
			return lc.ListenPacket(ctx, "udp", "")
		}, pubkey[:], ap, log.NewNOPFactory().Logger(), 16384, params)
		if err == nil {
			return tun, eng
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("rtc handshake never came up: %v", lastErr)
	return nil, nil
}

// TestRTCAxesRealServerMatchedEnv runs TWO independent knob sets, each against
// its own Rust server instance started with the matching env.
func TestRTCAxesRealServerMatchedEnv(t *testing.T) {
	cases := []struct {
		name          string
		chunk, window int
	}{
		{"chunk600_window32", 600, 32},
		{"chunk1024_window256", 1024, 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyPath := writeSharedKey(t)
			_, rtcAddr, pubkey, _ := startRustServerRTCEnv(t, keyPath,
				"HYDRA_RTC_CHUNK="+strconv.Itoa(tc.chunk),
				"HYDRA_RTC_WINDOW="+strconv.Itoa(tc.window))
			origin, roots := startProofOrigin(t, 64*1024)

			params := RtcChannelParams{Chunk: tc.chunk, Window: tc.window}
			tun, eng := dialRTCTunnelWithParams(t, rtcAddr, pubkey, params)
			defer tun.Close()

			// The proof body alone (64 KiB server->client) needs more than 4
			// data packets at any clamped chunk — assert the arithmetic first.
			minDataPkts := (64 * 1024) / tc.chunk
			if minDataPkts <= 4 {
				t.Fatalf("variant %s does not exercise >4 chunks", tc.name)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			if err := verifyTunnelProof(ctx, tun, proofTarget{URL: origin.URL, Bytes: 64 * 1024, TLS: &tls.Config{RootCAs: roots}}); err != nil {
				t.Fatalf("useful proof failed: %v", err)
			}

			// Direct >4-chunk transfer: 32 KiB echo roundtrip, byte-exact.
			echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))
			sess, err := tun.openSession(ctx, echoAddr, echoPort)
			if err != nil {
				t.Fatalf("open session: %v", err)
			}
			payload := make([]byte, 32*1024)
			for i := range payload {
				payload[i] = byte(i*31 + i/251)
			}
			go func() {
				_, _ = sess.Write(payload)
			}()
			got := make([]byte, len(payload))
			sess.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(sess, got); err != nil {
				t.Fatalf("echo read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo roundtrip corrupted")
			}

			// Wire divergence: the server chunked at ITS env value — full data
			// bodies are exactly 4 seq bytes + chunk, and the default-chunk
			// size never appears as a full body.
			histo := eng.snapshot()
			full := 4 + tc.chunk
			if histo[full] == 0 {
				t.Fatalf("server env chunk %d not observed on the wire (histogram %v)", tc.chunk, histo)
			}
			if histo[4+1150] != 0 {
				t.Fatalf("default chunk 1150 observed despite server env %d (histogram %v)", tc.chunk, histo)
			}
			t.Logf("variant %s: proof + 32 KiB echo passed; server full-chunk bodies (len=%d): %d, histogram=%v",
				tc.name, full, histo[full], histo)
		})
	}
}
