package hydra

// rtc:// outbound integration: the Go client against the REAL Rust
// hydra-server binary started with HYDRA_RTC_LISTEN (rtc_server.rs serves the
// WebRTC-masked UDP transport next to its ws TCP listener).
//
// Test A: static outbound options{transport:"rtc"} through the real outbound
// constructor — 64 KiB TCP echo byte-exact + a 128 KiB tunnel proof to an
// httptest origin.
// Test B: adaptive outbound with a dead ws endpoint and a live rtc endpoint —
// Acquire must promote the rtc one and the proof gate must pass (scheduler +
// rtc + proof chain).
// Test C: killing the rtc socket must dead-flag the tunnel and Acquire must
// rebuild a fresh verified rtc tunnel (recovery through rtc).
//
// Skipped when the binary is absent (HYDRA_SERVER_BIN overrides; the default
// points at the hydra-adaptive debug build, which is the one with rtc).

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const defaultRTCServerBin = "/home/varingait/src/hydra-adaptive/hydra/target/debug/hydra-server"

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// startRustServerRTC spawns hydra-server with BOTH its ws TCP listener (the
// positional arg) and the rtc UDP listener (HYDRA_RTC_LISTEN), one shared
// key file. Returns the ws address (unused by these tests, useful for
// debugging), the rtc address and the pubkey.
func startRustServerRTC(t *testing.T, keyPath string) (wsAddr string, rtcAddr string, pubkey [32]byte, stop func()) {
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

	wsPort := freePort(t)
	wsAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(wsPort))
	rtcAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(freeUDPPort(t)))

	var stderr syncBuffer
	cmd := exec.Command(bin, keyPath, wsAddr)
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	cmd.Env = append(os.Environ(), "HYDRA_DEBUG=1", "HYDRA_RTC_LISTEN="+rtcAddr)
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

	// Wait for the ws listener; the rtc listener starts in the same runtime
	// (connectRTCTunnel retries anyway in case it wins the race).
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

// syncBuffer is a small thread-safe bytes-ish sink for server stderr (the
// existing harness uses bytes.Buffer; the extra lock costs nothing here).
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// connectRTCTunnel dials the rtc transport directly (no outbound), retrying
// briefly so the just-started server's UDP listener is reliably up.
func connectRTCTunnel(t *testing.T, rtcAddr string, pubkey [32]byte, negotiateMaxFrame uint32) *Tunnel {
	t.Helper()
	ap, err := netip.ParseAddrPort(rtcAddr)
	if err != nil {
		t.Fatal(err)
	}
	var lastErr error
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		tun, err := connectTunnelRTC(t.Context(), func(ctx context.Context) (net.PacketConn, error) {
			var lc net.ListenConfig
			return lc.ListenPacket(ctx, "udp", "")
		}, pubkey[:], ap, nil, negotiateMaxFrame)
		if err == nil {
			return tun
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("rtc handshake never came up: %v", lastErr)
	return nil
}

func writeSharedKey(t *testing.T) string {
	t.Helper()
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(keyPath, []byte(encodeB64(sk)), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath
}

// startProofOrigin mirrors the real proof origin: X-Hydra-Nonce echo,
// explicit Content-Length (mandatory — bodies over 2 KiB would otherwise be
// sent chunked and ContentLength would read -1) and the SHA256 block stream.
func startProofOrigin(t *testing.T, size int) (origin *httptest.Server, roots *x509.CertPool) {
	t.Helper()
	origin = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		if requested, err := strconv.Atoi(r.URL.Query().Get("bytes")); err == nil && requested >= 1024 && requested <= 1048576 {
			size = requested
		}
		w.Header().Set("X-Hydra-Nonce", nonce)
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Write(proofTestBody(nonce, size))
	}))
	t.Cleanup(origin.Close)
	roots = x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	return origin, roots
}

func rtcCandidate(id, addr string, transport string) option.HydraAdaptiveCandidateOptions {
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	return option.HydraAdaptiveCandidateOptions{ID: id, ServerOptions: option.ServerOptions{Server: h, ServerPort: uint16(port)}, Transport: transport}
}

// TestRTCOutboundStaticE2E: static transport:"rtc" outbound — 64 KiB echo
// roundtrip through DialContext byte-exact, then a 128 KiB tunnel proof.
func TestRTCOutboundStaticE2E(t *testing.T) {
	keyPath := writeSharedKey(t)
	_, rtcAddr, pubkey, _ := startRustServerRTC(t, keyPath)
	origin, roots := startProofOrigin(t, 128*1024)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	h, p, _ := net.SplitHostPort(rtcAddr)
	port, _ := strconv.Atoi(p)
	opts := option.HydraOutboundOptions{
		ServerOptions:     option.ServerOptions{Server: h, ServerPort: uint16(port)},
		Pubkey:            encodeB64(pubkey[:]),
		Transport:         "rtc",
		NegotiateMaxFrame: 16384,
	}
	a, err := newStaticOutbound(t.Context(), log.NewNOPFactory().Logger(), "rtc-static", opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()

	payload := make([]byte, 65536)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	dest := M.SocksaddrFromNetIP(netip.AddrPortFrom(netip.MustParseAddr(echoAddr), echoPort))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn, err := o.DialContext(ctx, N.NetworkTCP, dest)
	if err != nil {
		t.Fatalf("dial through rtc outbound: %v", err)
	}
	roundtrip(t, conn, payload)
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	tun, err := o.getTunnel(ctx)
	if err != nil {
		t.Fatalf("getTunnel: %v", err)
	}
	if err := verifyTunnelProof(ctx, tun, proofTarget{URL: origin.URL, Bytes: 128 * 1024, TLS: &tls.Config{RootCAs: roots}}); err != nil {
		t.Fatalf("tunnel proof over rtc: %v", err)
	}
}

// TestRTCAdaptivePromotesRTC: a dead ws endpoint next to a live rtc endpoint
// — Acquire must promote the rtc candidate and the proof gate must pass.
func TestRTCAdaptivePromotesRTC(t *testing.T) {
	keyPath := writeSharedKey(t)
	_, rtcAddr, pubkey, _ := startRustServerRTC(t, keyPath)
	origin, roots := startProofOrigin(t, 1024)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	// Dead ws endpoint: TCP accepts, the ws upgrade never completes.
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	go func() {
		for {
			c, err := blackhole.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 4096)
				for {
					if _, err := c.Read(b); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	opts := option.HydraOutboundOptions{
		Pubkey: encodeB64(pubkey[:]),
		Adaptive: &option.HydraAdaptiveOptions{
			Candidates:     []option.HydraAdaptiveCandidateOptions{rtcCandidate("dead-ws", blackhole.Addr().String(), "wss"), rtcCandidate("rtc", rtcAddr, "rtc")},
			ProofURL:       origin.URL,
			ProofBytes:     1024,
			AttemptTimeout: badoption.Duration(2 * time.Second),
		},
	}
	a, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, log.NewNOPFactory().Logger(), "rtc-promote", opts, adaptiveOutboundDependencies{
		ProofTLS: &tls.Config{RootCAs: roots},
		DialerFactory: func(ctx context.Context, candidate option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
			return dialer.New(ctx, candidate.DialerOptions, candidate.ServerIsDomain())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	tun, err := o.getTunnel(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if o.adaptiveSnapshot().ActiveID != "rtc" {
		t.Fatalf("active candidate = %q, want rtc", o.adaptiveSnapshot().ActiveID)
	}
	s, err := tun.openSession(ctx, echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open over promoted rtc tunnel: %v", err)
	}
	roundtrip(t, s, []byte("adaptive-rtc-promoted"))
	_ = s.Close()
}

// TestRTCAdaptiveRebuildAfterSocketClose: close the rtc socket under a live
// tunnel — the tunnel dead-flags and Acquire rebuilds a fresh verified rtc
// tunnel.
func TestRTCAdaptiveRebuildAfterSocketClose(t *testing.T) {
	keyPath := writeSharedKey(t)
	_, rtcAddr, pubkey, _ := startRustServerRTC(t, keyPath)
	origin, roots := startProofOrigin(t, 1024)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	opts := option.HydraOutboundOptions{
		Pubkey: encodeB64(pubkey[:]),
		Adaptive: &option.HydraAdaptiveOptions{
			Candidates: []option.HydraAdaptiveCandidateOptions{rtcCandidate("rtc", rtcAddr, "rtc")},
			ProofURL:   origin.URL,
			ProofBytes: 1024,
		},
	}
	a, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, log.NewNOPFactory().Logger(), "rtc-rebuild", opts, adaptiveOutboundDependencies{
		ProofTLS: &tls.Config{RootCAs: roots},
		DialerFactory: func(ctx context.Context, candidate option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
			return dialer.New(ctx, candidate.DialerOptions, candidate.ServerIsDomain())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	tun1, err := o.getTunnel(ctx)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	s1, err := tun1.openSession(ctx, echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	roundtrip(t, s1, []byte("before-death"))
	_ = s1.Close()

	// Kill the rtc socket the way a network break does: Tunnel.Close closes
	// the underlying UDP PacketConn.
	_ = tun1.Close()
	deadline := time.Now().Add(3 * time.Second)
	for !tun1.IsDead() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tun1.IsDead() {
		t.Fatal("rtc tunnel must be dead after socket close")
	}

	// Acquire must rebuild a fresh verified rtc tunnel.
	var tun2 *Tunnel
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		t, err := o.getTunnel(ctx)
		if err == nil && t != tun1 && !t.IsDead() {
			tun2 = t
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if tun2 == nil {
		t.Fatal("acquire did not rebuild after rtc socket death")
	}
	if o.adaptiveSnapshot().ActiveID != "rtc" {
		t.Fatalf("active candidate = %q after rebuild, want rtc", o.adaptiveSnapshot().ActiveID)
	}
	s2, err := tun2.openSession(ctx, echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	roundtrip(t, s2, []byte("after-death"))
	_ = s2.Close()
}
