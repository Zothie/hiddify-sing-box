package hydra

// Cross-implementation E2E: this Go client against the REAL Rust
// hydra-server binary (target/release/hydra-server from vpns/hydra).
// Skipped when the binary is absent (set HYDRA_SERVER_BIN to override).

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

const defaultServerBin = "/media/varingait/Lobotomite/vpns/hydra/target/release/hydra-server"

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startRustServer spawns hydra-server with a fresh keypair on a free port.
func startRustServer(t *testing.T) (serverAddr string, pubkey [32]byte, stop func()) {
	t.Helper()
	bin := os.Getenv("HYDRA_SERVER_BIN")
	if bin == "" {
		bin = defaultServerBin
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("hydra-server binary not present (%s): %v", bin, err)
	}
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	pk, err := x25519Pub(sk)
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	serverAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(port))

	var stderr bytes.Buffer
	cmd := exec.Command(bin, encodeB64(sk), serverAddr)
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	cmd.Env = append(os.Environ(), "HYDRA_DEBUG=1")
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

	// Wait for the ws listener.
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", serverAddr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hydra-server did not listen on %s; stderr:\n%s", serverAddr, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	var kp [32]byte
	copy(kp[:], pk)
	return serverAddr, kp, stop
}

// startTCPEcho runs a half-close-aware echo server: after echoing everything
// up to a client FIN it closes, so the Rust server observes EOF and sends
// CLOSE [4] back through the tunnel.
func startTCPEcho(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return l.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

// connectTestTunnel opens a plain ws:// tunnel to the Rust server.
func connectTestTunnel(t *testing.T, serverAddr string, pubkey [32]byte) *Tunnel {
	t.Helper()
	nd := &net.Dialer{Timeout: handshakeTimeout}
	dialFn := func(ctx context.Context) (net.Conn, error) {
		return nd.DialContext(ctx, "tcp", serverAddr)
	}
	requestURL := url.URL{Scheme: "ws", Host: serverAddr, Path: "/"}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	tun, err := connectTunnel(context.Background(), dialFn, &requestURL, headers, pubkey[:], nil)
	if err != nil {
		t.Fatalf("connectTunnel: %v", err)
	}
	return tun
}

func roundtrip(t testing.TB, conn net.Conn, payload []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("roundtrip payload mismatch")
	}
}

// TestE2ETCP: OPEN to a local echo server, 8 KiB roundtrip, then two
// interleaved sessions running concurrent roundtrips over one tunnel.
func TestE2ETCP(t *testing.T) {
	serverAddr, pubkey, _ := startRustServer(t)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))
	tun := connectTestTunnel(t, serverAddr, pubkey)
	defer tun.Close()

	s1, err := tun.openSession(t.Context(), echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open s1: %v", err)
	}
	payload8K := make([]byte, 8192)
	if _, err := rand.Read(payload8K); err != nil {
		t.Fatal(err)
	}
	roundtrip(t, s1, payload8K)

	s2, err := tun.openSession(t.Context(), echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open s2: %v", err)
	}
	var wg sync.WaitGroup
	for _, s := range []*session{s1, s2} {
		wg.Add(1)
		go func(s *session) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				roundtrip(t, s, bytes.Repeat([]byte{byte(i)}, 3000+i))
			}
		}(s)
	}
	wg.Wait()
	_ = s1.Close()
	_ = s2.Close()
}

// TestE2EOpenFailure: opening to a dead target must come back as a failed
// OPEN-REPLY (server sends [3][id][0][n][errmsg]), not a timeout.
func TestE2EOpenFailure(t *testing.T) {
	serverAddr, pubkey, _ := startRustServer(t)
	tun := connectTestTunnel(t, serverAddr, pubkey)
	defer tun.Close()
	deadPort := freePort(t) // nothing listens there
	_, err := tun.openSession(t.Context(), "127.0.0.1", uint16(deadPort))
	if err == nil {
		t.Fatal("open to dead target must fail")
	}
}

// TestE2EUDP: datagram roundtrip through the Rust server's UDP relay.
func TestE2EUDP(t *testing.T) {
	serverAddr, pubkey, _ := startRustServer(t)
	echoAddr := startUDPEcho(t)
	tun := connectTestTunnel(t, serverAddr, pubkey)
	defer tun.Close()

	pc, err := net.ResolveUDPAddr("udp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	udp := tun.openUDP()
	defer udp.Close()
	payload := bytes.Repeat([]byte("udp-e2e-"), 100) // 800 bytes
	if _, err := udp.WriteTo(payload, pc); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	n, from, err := udp.ReadFrom(got)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != len(payload) || !bytes.Equal(got, payload) {
		t.Fatalf("udp payload mismatch (n=%d)", n)
	}
	if from == nil {
		t.Fatal("nil source addr")
	}
}

// TestE2EHalfClose: write payload, CloseWrite (HALF-CLOSE [7]) — the echo
// data must still come back and then EOF arrive when the Rust server relays
// the upstream FIN/CLOSE.
func TestE2EHalfClose(t *testing.T) {
	serverAddr, pubkey, _ := startRustServer(t)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))
	tun := connectTestTunnel(t, serverAddr, pubkey)
	defer tun.Close()

	s, err := tun.openSession(t.Context(), echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.Write([]byte("goodbye")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read-until-EOF: %v", err)
	}
	if string(got) != "goodbye" {
		t.Fatalf("half-close echo got %q", got)
	}
	// Double close / close after half-close must be safe.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("double Close: %v", err)
	}
}

// TestE2EReconnect: after the tunnel dies, a fresh dial must transparently
// rebuild and work (Rust TunnelHandle dead-flag + rebuild semantics).
func TestE2EReconnect(t *testing.T) {
	serverAddr, pubkey, stopServer := startRustServer(t)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	tun := connectTestTunnel(t, serverAddr, pubkey)
	s, err := tun.openSession(t.Context(), echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	roundtrip(t, s, []byte("before-death"))
	_ = s.Close()
	// Simulate transport death the way a network break does.
	_ = tun.Close()
	// Wait for the pipes to actually notice (raw.Close unblocks the reader).
	deadline := time.Now().Add(3 * time.Second)
	for !tun.IsDead() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tun.IsDead() {
		t.Fatal("tunnel must be dead after Close")
	}

	// Fresh tunnel: same as the Rust client rebuilding after dead-flag.
	tun2 := connectTestTunnel(t, serverAddr, pubkey)
	defer tun2.Close()
	s2, err := tun2.openSession(t.Context(), echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open after rebuild: %v", err)
	}
	roundtrip(t, s2, []byte("after-death"))
	_ = s2.Close()
	_ = stopServer
}

func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	fmt.Sscan(p, &port)
	return "127.0.0.1", uint16(port)
}
