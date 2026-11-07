package hydra

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// fakeConn records every Write as a separate segment.
type fakeConn struct {
	segments [][]byte
	closed   bool
}

func (c *fakeConn) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	c.segments = append(c.segments, cp)
	return len(b), nil
}

func (c *fakeConn) Read(b []byte) (int, error)         { return 0, errors.New("read") }
func (c *fakeConn) Close() error                       { c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHelloSplitFirstRecord(t *testing.T) {
	fc := &fakeConn{}
	c := newHelloSplitConn(fc)
	payload := make([]byte, 517) // typical ClientHello record size
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if len(fc.segments) < 2 {
		t.Fatalf("expected >=2 segments, got %d", len(fc.segments))
	}
	first := len(fc.segments[0])
	if first < splitFirstMin || first > splitFirstMax {
		t.Fatalf("first segment %d outside [%d,%d]", first, splitFirstMin, splitFirstMax)
	}
	for i, seg := range fc.segments[1:] {
		if len(seg) > splitRestMax {
			t.Fatalf("segment %d len %d > %d", i, len(seg), splitRestMax)
		}
	}
	var got bytes.Buffer
	for _, seg := range fc.segments {
		got.Write(seg)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatal("payload corrupted by splitting")
	}
}

func TestHelloSplitSubsequentWritesPassThrough(t *testing.T) {
	fc := &fakeConn{}
	c := newHelloSplitConn(fc)
	c.Write(make([]byte, 300))
	n := len(fc.segments)
	c.Write(make([]byte, 400))
	if len(fc.segments) != n+1 {
		t.Fatalf("second write must NOT be split: %d -> %d segments", n, len(fc.segments))
	}
}

// --- parameterised axes ------------------------------------------------------

// TestSplitDefaultsMatchRust: SplitParams{} must resolve to the Rust client's
// frag.rs baseline (TUNING.md 01-hydra-wss-frag.md): first cut random in
// [8,64], rest pieces random in [16,96] (never the legacy fixed 96), a 1ms
// SPLIT_DELAY between first-flight segments, and a record no larger than the
// first-segment ceiling going out unsplit.
func TestSplitDefaultsMatchRust(t *testing.T) {
	payload := make([]byte, 517)
	for i := range payload {
		payload[i] = byte(i % 253)
	}
	sawSmallRest := false
	for conn := 0; conn < 3; conn++ {
		fc := &fakeConn{}
		c := newHelloSplitConnParams(fc, SplitParams{})
		start := time.Now()
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)
		if c.SegmentsWritten() != len(fc.segments) {
			t.Fatalf("segment counter %d != recorded %d", c.SegmentsWritten(), len(fc.segments))
		}
		if first := len(fc.segments[0]); first < splitFirstMin || first > splitFirstMax {
			t.Fatalf("conn %d: first cut %d outside [%d,%d]", conn, first, splitFirstMin, splitFirstMax)
		}
		rest := fc.segments[1:]
		if len(rest) < 2 {
			t.Fatalf("conn %d: 517B payload must yield several rest pieces, got %d", conn, len(rest))
		}
		for i, seg := range rest[:len(rest)-1] {
			// [16,96] literals: the splitRestMin default lands with the
			// split.go change this test drives.
			if s := len(seg); s < 16 || s > 96 {
				t.Fatalf("conn %d: rest piece %d is %d bytes, outside [16,96]", conn, i, s)
			} else if s < 96 {
				sawSmallRest = true
			}
		}
		if last := len(rest[len(rest)-1]); last > splitRestMax {
			t.Fatalf("conn %d: last piece %d > %d", conn, last, splitRestMax)
		}
		// SPLIT_DELAY default 1ms: one sleep per inter-segment gap (Go sleeps
		// at least the requested duration, so the bound is hard).
		if want := time.Duration(len(fc.segments)-1) * time.Millisecond; elapsed < want {
			t.Fatalf("conn %d: %d segments took %v, want >= %v of default 1ms pacing",
				conn, len(fc.segments), elapsed, want)
		}
		var got bytes.Buffer
		for _, seg := range fc.segments {
			got.Write(seg)
		}
		if !bytes.Equal(got.Bytes(), payload) {
			t.Fatalf("conn %d: payload corrupted", conn)
		}
	}
	if !sawSmallRest {
		t.Fatal("rest range not randomized: every non-final piece was exactly 96 across 3 connections")
	}
	// Rust frag.rs:43-45: a record no larger than the first-segment ceiling
	// is never split at all.
	fc := &fakeConn{}
	c := newHelloSplitConnParams(fc, SplitParams{})
	if _, err := c.Write(make([]byte, 60)); err != nil {
		t.Fatal(err)
	}
	if len(fc.segments) != 1 {
		t.Fatalf("60B payload (<= firstMax 64) must go unsplit, got %d segments", len(fc.segments))
	}
}

// TestSplitKnobLiveness (axis proof c): shrinking the ranges must grow the
// segment count on the recorded wire; the first cut must be random per
// connection when the range is open and fixed when min==max; clamps must hold
// for out-of-range catalogue values.
func TestSplitKnobLiveness(t *testing.T) {
	payload := make([]byte, 517)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	write := func(p SplitParams) (int, []int) {
		fc := &fakeConn{}
		c := newHelloSplitConnParams(fc, p)
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		sizes := make([]int, len(fc.segments))
		for i, seg := range fc.segments {
			sizes[i] = len(seg)
		}
		return c.SegmentsWritten(), sizes
	}

	tight, _ := write(SplitParams{FirstMin: 1, FirstMax: 1, RestMin: 1, RestMax: 1})
	wide, _ := write(SplitParams{FirstMin: 64, FirstMax: 64, RestMin: 96, RestMax: 96})
	// The 1-byte pathological rest is raised to the server attack budget
	// (maxAttackBudgetPieces: tungstenite AttackCheck resets >64-read
	// flights — measured live), so the count caps near the budget instead
	// of the raw 517 (the exact cap depends on the ceil rounding of the
	// raised rest floor); it still fragments far more than the wide range.
	if tight > maxAttackBudgetPieces+1 || tight <= wide {
		t.Fatalf("1-byte pieces: want budget-capped %d..%d segments and more than wide (%d), got %d",
			wide+1, maxAttackBudgetPieces+1, wide, tight)
	}

	// Random per connection within the caller range: first cut spreads over
	// 20..30 across connections, every value stays inside the range.
	seen := make(map[int]bool)
	for i := 0; i < 40; i++ {
		_, sizes := write(SplitParams{FirstMin: 20, FirstMax: 30, RestMin: 40, RestMax: 80})
		if sizes[0] < 20 || sizes[0] > 30 {
			t.Fatalf("first cut %d outside [20,30]", sizes[0])
		}
		for j, s := range sizes[1 : len(sizes)-1] {
			if s < 40 || s > 80 {
				t.Fatalf("rest piece %d is %d, outside [40,80]", j, s)
			}
		}
		seen[sizes[0]] = true
	}
	if len(seen) < 2 {
		t.Fatalf("first cut never varied across 40 connections: %v", seen)
	}

	// Fixed (min==max) never varies and is byte-exact.
	for i := 0; i < 10; i++ {
		_, sizes := write(SplitParams{FirstMin: 32, FirstMax: 32, RestMin: 16, RestMax: 16})
		if sizes[0] != 32 {
			t.Fatalf("fixed first cut moved: %d", sizes[0])
		}
		for j, s := range sizes[1 : len(sizes)-1] {
			if s != 16 {
				t.Fatalf("fixed rest piece %d is %d, want 16", j, s)
			}
		}
	}

	// Clamps: out-of-range catalogue values land inside 1..64 / 1..96.
	for i := 0; i < 10; i++ {
		_, sizes := write(SplitParams{FirstMin: -5, FirstMax: 1000, RestMin: -1, RestMax: 500})
		if sizes[0] < 1 || sizes[0] > 64 {
			t.Fatalf("clamped first cut %d outside [1,64]", sizes[0])
		}
		for j, s := range sizes[1 : len(sizes)-1] {
			if s < 1 || s > 96 {
				t.Fatalf("clamped rest piece %d is %d, outside [1,96]", j, s)
			}
		}
	}
}

// TestSplitDelayKnob: split_delay_ms must really sleep between the segments
// of the first flight and must not fire for later writes.
func TestSplitDelayKnob(t *testing.T) {
	payload := make([]byte, 300)
	fc := &fakeConn{}
	c := newHelloSplitConnParams(fc, SplitParams{FirstMin: 10, FirstMax: 10, RestMin: 10, RestMax: 10, SplitDelayMs: 5})
	start := time.Now()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	pieces := len(fc.segments) - 1 // sleeps only between segments
	if pieces < 20 {
		t.Fatalf("expected >=21 segments, got %d", len(fc.segments))
	}
	if minElapsed := time.Duration(pieces) * 4 * time.Millisecond; elapsed < minElapsed {
		t.Fatalf("%d segments with 5ms delay took %v, want >= %v", len(fc.segments), elapsed, minElapsed)
	}
	// Second write: no split, no delay.
	start = time.Now()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Millisecond {
		t.Fatalf("follow-up write delayed by %v; split delay must apply to the first flight only", d)
	}
}

// --- dialer-level disorder ---------------------------------------------------

// plainNetDialer adapts a *net.Dialer to N.Dialer for the transport tests.
type plainNetDialer struct {
	d net.Dialer
}

func (d plainNetDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.d.DialContext(ctx, network, destination.String())
}

func (d plainNetDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

// TestSplitDisorderFallbackNonTCP: on a non-TCP conn the disorder dialer must
// hand back the plain conn (fragmentation fallback), never fail the dial.
func TestSplitDisorderFallbackNonTCP(t *testing.T) {
	fc := &fakeConn{}
	d := ttlDisorderDialer{
		Dialer: plainNetDialerStub{conn: fc},
		Params: SplitParams{Disorder: true},
	}
	c, err := d.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	if err != nil {
		t.Fatalf("fallback dial failed: %v", err)
	}
	if _, isDisorder := c.(*ttlDisorderConn); isDisorder {
		t.Fatal("non-TCP conn must not be wrapped by the disorder conn")
	}
	if c != net.Conn(fc) {
		t.Fatal("fallback must return the original conn")
	}
}

type plainNetDialerStub struct{ conn net.Conn }

func (d plainNetDialerStub) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d plainNetDialerStub) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

// --- real-server integration (a): custom ranges + disorder mechanics --------

// startSplitRustServer spawns the real Rust hydra-server bound to bindAddr.
func startSplitRustServer(t *testing.T, bindAddr string) (serverAddr string, pubkey [32]byte, stop func()) {
	t.Helper()
	bin := os.Getenv("HYDRA_SERVER_BIN")
	if bin == "" {
		bin = defaultServerBin
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("hydra-server binary not present (%s): %v", bin, err)
	}
	sk := make([]byte, 32)
	keyPath := filepath.Join(t.TempDir(), "server.key")
	for i := range sk {
		sk[i] = byte(i*7 + 1)
	}
	if err := os.WriteFile(keyPath, []byte(encodeB64(sk)), 0o600); err != nil {
		t.Fatal(err)
	}
	pk, err := x25519Pub(sk)
	if err != nil {
		t.Fatal(err)
	}
	var kp [32]byte
	copy(kp[:], pk)

	l, err := net.Listen("tcp", bindAddr+":0")
	if err != nil {
		t.Fatalf("probe %s: %v", bindAddr, err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	serverAddr = net.JoinHostPort(bindAddr, strconv.Itoa(port))

	var stderr bytes.Buffer
	cmd := exec.Command(bin, keyPath, serverAddr)
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
	stop = func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
	t.Cleanup(stop)

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
	return serverAddr, kp, stop
}

// splitTestTunnel opens a tunnel whose transport is the production split
// dialer stack (helloSplitConn over the optional disorder conn) with custom
// catalogue ranges, and reports the observed state of both wrappers.
func splitTestTunnel(t *testing.T, serverAddr string, pubkey [32]byte, params SplitParams) (*Tunnel, int, *ttlDisorderConn) {
	t.Helper()
	var gotConn net.Conn
	transport := splitDialer{Dialer: ttlDisorderDialer{Dialer: plainNetDialer{}, Params: params}, Params: params}
	dialFn := func(ctx context.Context) (net.Conn, error) {
		c, err := transport.DialContext(ctx, "tcp", M.ParseSocksaddr(serverAddr))
		if err == nil {
			gotConn = c
		}
		return c, err
	}
	requestURL := url.URL{Scheme: "ws", Host: serverAddr, Path: "/"}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	start := time.Now()
	tun, err := connectTunnel(context.Background(), dialFn, &requestURL, headers, pubkey[:], nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("connectTunnel (params %+v) after %v: %v", params, elapsed, err)
	}
	split, _ := gotConn.(*helloSplitConn)
	if split == nil {
		t.Fatal("transport must return a helloSplitConn")
	}
	dc, _ := split.Conn.(*ttlDisorderConn) // nil when disorder disabled
	return tun, split.SegmentsWritten(), dc
}

// TestHydraSplitLoopbackRealServer: the REAL Rust hydra-server must accept a
// full handshake+proof (HELLO/CONFIRM) over a transport built with custom
// catalogue ranges, with and without the TTL=1 disorder arm.
//
// NOTE: loopback does NOT decrement TTL (there is no router hop on 127.0.0.1),
// so this test proves the mechanics only - TTL=1 is armed on the socket, the
// saved TTL is restored after the first flight, the server still receives
// everything. The real death branch lives in the netns/veth lab test below.
//
// WIRE CONSTRAINT (measured): the Rust server's tungstenite handshake layer
// rejects an upgrade arriving in more than 64 packets averaging under 128
// bytes ("Attack attempt detected", RST). Catalogue ranges must therefore
// keep the first-flight piece count well under 64 for typical upgrade sizes;
// these tests use legal, realistic ranges only (>=8-byte pieces).
func TestHydraSplitLoopbackRealServer(t *testing.T) {
	serverAddr, pubkey, _ := startSplitRustServer(t, "127.0.0.1")

	// (a1) custom ranges + split delay, disorder off.
	ranges := SplitParams{FirstMin: 20, FirstMax: 30, RestMin: 40, RestMax: 80, SplitDelayMs: 5}
	tun, segments, dc := splitTestTunnel(t, serverAddr, pubkey, ranges)
	if segments <= 1 {
		t.Fatalf("custom ranges produced %d segments; splitter not engaged", segments)
	}
	if dc != nil {
		t.Fatal("disorder conn must be absent when Disorder is off")
	}
	roundtrip(t, tunnelProbe(t, tun), bytes.Repeat([]byte{0xAB}, 512))
	tun.Close()

	// (a2) the same ranges with the disorder arm enabled.
	params := ranges
	params.Disorder = true
	params.DisorderDelayMs = 10
	tun, segments, dc = splitTestTunnel(t, serverAddr, pubkey, params)
	defer tun.Close()
	if segments <= 1 {
		t.Fatalf("custom ranges with disorder produced %d segments", segments)
	}
	if dc == nil {
		t.Fatal("disorder conn missing under the split transport")
	}
	if !dc.Applied() {
		t.Fatal("disorder conn must report TTL=1 armed after dial")
	}
	if !dc.Restored() {
		t.Fatal("saved TTL must be restored once the first flight went out")
	}
	if dc.SavedTTL() <= 0 {
		t.Fatalf("saved TTL %d must be read from the socket", dc.SavedTTL())
	}
	// Restore() is idempotent and always returns the saved value.
	if restored := dc.Restore(); restored != dc.SavedTTL() {
		t.Fatalf("Restore returned %d, want the saved %d", restored, dc.SavedTTL())
	}

	// (a3) knob liveness on the real path: tight legal ranges (fixed 8-byte
	// first cut, 16-byte pieces) must fragment the WS-upgrade far more than
	// the wide ranges above, while staying inside the server's AttackCheck
	// packet budget (<=64 packets averaging >=128B).
	tun, tight, _ := splitTestTunnel(t, serverAddr, pubkey,
		SplitParams{FirstMin: 8, FirstMax: 8, RestMin: 16, RestMax: 16})
	defer tun.Close()
	if tight <= segments {
		t.Fatalf("tight ranges gave %d segments, must exceed wide-range %d", tight, segments)
	}
}

// tunnelProbe opens one echo-backed session for a quick post-handshake
// roundtrip through the tunnel.
func tunnelProbe(t *testing.T, tun *Tunnel) net.Conn {
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
	addr, port := splitHostPort(t, l.Addr().String())
	s, err := tun.openSession(context.Background(), addr, port)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// --- real death branch (b): netns/veth lab with a router hop -----------------

const (
	netnsChildFlagEnv = "HYDRA_SPLIT_NETNS_CHILD"
	netnsChildModeEnv = "HYDRA_SPLIT_CHILD_MODE"
	netnsChildAddrEnv = "HYDRA_SPLIT_CHILD_ADDR"
	netnsChildKeyEnv  = "HYDRA_SPLIT_CHILD_KEY"
	netnsChildCtrlEnv = "HYDRA_SPLIT_CHILD_CONTROL_MS"
	netnsChildDelayE  = "HYDRA_SPLIT_CHILD_DELAY"
)

// TestHydraDisorderNetnsDeathBranch proves the honest death branch of the
// disorder axis: the client sits in a netns behind a ROUTER netns (one real
// L3 hop), so its TTL=1 segment is dropped by the router; after the saved TTL
// is restored TCP retransmits with the normal TTL and the handshake completes.
// A tcpdump on the router's client-facing interface records the dying packet.
// Skipped (with reason) when sudo, iproute2 or the Rust server are missing.
func TestHydraDisorderNetnsDeathBranch(t *testing.T) {
	if os.Getenv(netnsChildFlagEnv) == "1" {
		runNetnsChild(t) // re-executed inside the client netns
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("netns lab needs linux")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skipf("iproute2 unavailable: %v", err)
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skipf("passwordless sudo unavailable: %v", err)
	}
	bin := os.Getenv("HYDRA_SERVER_BIN")
	if bin == "" {
		bin = defaultServerBin
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("hydra-server binary not present (%s): %v", bin, err)
	}
	if os.Getenv("HYDRA_SPLIT_SKIP_NETNS") == "1" {
		t.Skip("netns lab disabled via HYDRA_SPLIT_SKIP_NETNS=1")
	}

	nsC := fmt.Sprintf("hysplitc%d", os.Getpid())
	nsR := fmt.Sprintf("hysplitr%d", os.Getpid())
	// 10.213.61/62 (NOT .41/.42): other netns labs on this host claim those.
	hostIP := "10.213.62.2"
	cleanup := buildNetnsLab(t, nsC, nsR)
	defer cleanup()

	// Lab sanity: with the router as the only hop, a TTL=1 probe must die
	// there (forwarding decrements it to 0 and the kernel drops it).
	sanity := sudoOutput(append([]string{"-n"}, netnsExec(nsC,
		"ping", "-c1", "-W2", "-t", "1", hostIP)...)...)
	if !strings.Contains(sanity, "100% packet loss") {
		t.Fatalf("lab sanity failed: TTL=1 ping survived the router hop:\n%s", sanity)
	}

	serverAddr, keyPath, stopServer := startNetnsServer(t, hostIP)
	defer stopServer()

	// Control pass: identical transport WITHOUT disorder, same lab.
	ctrlMS := runNetnsChildPass(t, nsC, "control", serverAddr, keyPath, 0)
	if ctrlMS >= 2000 {
		t.Fatalf("control pass took %dms; lab is too slow to prove the death branch", ctrlMS)
	}

	// Definitive evidence: capture the client's data segments on the router's
	// client-facing interface during the disorder pass. The first flight
	// segment must appear twice: once with TTL=1 (dropped at the hop) and
	// again with the restored TTL (the retransmission that completes the
	// handshake). Recovery is dupack-driven fast retransmit, so the wall
	// clock of the two passes may differ by only milliseconds.
	capture := startRouterCapture(t, nsR, "hyr0", "10.213.61.2")

	disMS := runNetnsChildPass(t, nsC, "disorder", serverAddr, keyPath, ctrlMS)
	t.Logf("lab timings: control=%dms disorder=%dms", ctrlMS, disMS)

	captureLines, err := capture(15 * time.Second)
	if err != nil {
		t.Fatalf("router capture failed: %v", err)
	}
	lost, retrans, ok := findTTLDeath(captureLines)
	if !ok {
		t.Fatalf("no TTL=1 segment + same-seq retransmit seen at the router hop; capture:\n%s",
			strings.Join(captureLines, "\n"))
	}
	t.Logf("death branch proven: control %dms, disorder %dms; first segment seq %d..%d went out with TTL=1 (dropped at the hop) and was retransmitted with the restored TTL (seq %d..%d)",
		ctrlMS, disMS, lost[0], lost[1], retrans[0], retrans[1])
}

// netnsExec prefixes a command with `ip netns exec <ns>`.
func netnsExec(ns string, args ...string) []string {
	return append([]string{"ip", "netns", "exec", ns}, args...)
}

// sudoOutput runs one command under passwordless sudo and returns combined
// output (strict=false semantics: errors surface only through the output).
func sudoOutput(args ...string) string {
	out, _ := exec.Command("sudo", args...).CombinedOutput()
	return string(out)
}

// findTTLDeath scans tcpdump -n -v lines for the disorder death signature:
// one TCP data segment that first appears with ttl 1 and, later, with a
// higher ttl as the retransmission of the very same seq range. tcpdump -v
// splits every packet over two lines: the IP header (ttl) and the indented
// TCP details (seq).
func findTTLDeath(lines []string) (lost, retrans [2]int64, ok bool) {
	type seg struct {
		ttl int
		lo  int64
		hi  int64
	}
	var segs []seg
	reTTL := regexp.MustCompile(`ttl (\d+),`)
	reSeq := regexp.MustCompile(`Flags \[[^\]]*\].*?seq (\d+):(\d+)`)
	pending := -1
	for _, line := range lines {
		if m := reTTL.FindStringSubmatch(line); m != nil {
			pending, _ = strconv.Atoi(m[1])
			continue
		}
		if pending < 0 {
			continue
		}
		if m := reSeq.FindStringSubmatch(line); m != nil {
			lo, _ := strconv.ParseInt(m[1], 10, 64)
			hi, _ := strconv.ParseInt(m[2], 10, 64)
			segs = append(segs, seg{pending, lo, hi})
		}
		pending = -1
	}
	for i, s := range segs {
		if s.ttl != 1 {
			continue
		}
		for _, t := range segs[i+1:] {
			if t.ttl > 1 && t.lo == s.lo && t.hi == s.hi {
				return [2]int64{s.lo, s.hi}, [2]int64{t.lo, t.hi}, true
			}
		}
	}
	return [2]int64{}, [2]int64{}, false
}

// buildNetnsLab creates the client netns and a router netns joined by two
// veth pairs, enables forwarding on the router and points everything at it:
//
//	client ns (10.213.61.2) --hyr0-- router ns --hyrh0-- host (10.213.62.2)
//
// The client's default route via the router makes the router the first hop.
func buildNetnsLab(t *testing.T, nsC, nsR string) func() {
	t.Helper()
	sudo := func(strict bool, args ...string) string {
		cmd := append([]string{"-n"}, args...)
		out, err := exec.Command("sudo", cmd...).CombinedOutput()
		if err != nil && strict {
			t.Fatalf("sudo %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	inNetns := func(ns string, args ...string) []string {
		return append([]string{"ip", "netns", "exec", ns}, args...)
	}
	cleanup := func() {
		bestEffortSudo("ip", "netns", "del", nsC)
		bestEffortSudo("ip", "netns", "del", nsR)
		bestEffortSudo("ip", "link", "del", "hyh0")
		bestEffortSudo("ip", "route", "del", "10.213.61.0/24")
	}
	t.Cleanup(cleanup)

	// Pre-clean leftovers from a SIGKILLed previous run (its t.Cleanup never
	// fired) before creating anything, or "File exists" kills the build.
	bestEffortSudo("ip", "netns", "del", nsC)
	bestEffortSudo("ip", "netns", "del", nsR)
	bestEffortSudo("ip", "link", "del", "hyh0")
	bestEffortSudo("ip", "link", "del", "hyrh0")
	bestEffortSudo("ip", "link", "del", "hyc0")
	bestEffortSudo("ip", "route", "del", "10.213.61.0/24")

	sudo(true, "ip", "netns", "add", nsC)
	sudo(true, "ip", "netns", "add", nsR)
	sudo(true, "ip", "link", "add", "hyc0", "type", "veth", "peer", "name", "hyr0")
	sudo(true, "ip", "link", "set", "hyr0", "netns", nsR)
	sudo(true, "ip", "link", "add", "hyrh0", "type", "veth", "peer", "name", "hyh0")
	sudo(true, "ip", "link", "set", "hyrh0", "netns", nsR)
	sudo(true, "ip", "link", "set", "hyc0", "netns", nsC)

	// Client ns: one interface, default route via the router.
	sudo(true, inNetns(nsC, "ip", "link", "set", "lo", "up")...)
	sudo(true, inNetns(nsC, "ip", "addr", "add", "10.213.61.2/24", "dev", "hyc0")...)
	sudo(true, inNetns(nsC, "ip", "link", "set", "hyc0", "up")...)
	sudo(true, inNetns(nsC, "ip", "route", "add", "default", "via", "10.213.61.1")...)
	sudo(true, inNetns(nsC, "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")...)

	// Router ns: both veths up, forwarding on, rp_filter off.
	sudo(true, inNetns(nsR, "ip", "link", "set", "lo", "up")...)
	sudo(true, inNetns(nsR, "ip", "addr", "add", "10.213.61.1/24", "dev", "hyr0")...)
	sudo(true, inNetns(nsR, "ip", "addr", "add", "10.213.62.1/24", "dev", "hyrh0")...)
	sudo(true, inNetns(nsR, "ip", "link", "set", "hyr0", "up")...)
	sudo(true, inNetns(nsR, "ip", "link", "set", "hyrh0", "up")...)
	sudo(true, inNetns(nsR, "sysctl", "-w", "net.ipv4.ip_forward=1")...)
	sudo(true, inNetns(nsR, "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")...)

	// Host: lab address + return route to the client via the router.
	sudo(true, "ip", "addr", "add", "10.213.62.2/24", "dev", "hyh0")
	sudo(true, "ip", "link", "set", "hyh0", "up")
	sudo(true, "ip", "route", "add", "10.213.61.0/24", "via", "10.213.62.1", "dev", "hyh0")
	return cleanup
}

// bestEffortSudo runs one privileged lab command and ignores the outcome.
func bestEffortSudo(args ...string) {
	_, _ = exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput()
}

// startNetnsServer binds the real Rust hydra-server on the host-side lab IP.
func startNetnsServer(t *testing.T, hostIP string) (serverAddr, keyPath string, stop func()) {
	t.Helper()
	bin := os.Getenv("HYDRA_SERVER_BIN")
	if bin == "" {
		bin = defaultServerBin
	}
	sk := make([]byte, 32)
	for i := range sk {
		sk[i] = byte(i*13 + 5)
	}
	keyPath = filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(keyPath, []byte(encodeB64(sk)), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", hostIP+":0")
	if err != nil {
		t.Fatalf("probe %s: %v", hostIP, err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	serverAddr = net.JoinHostPort(hostIP, strconv.Itoa(port))
	var stderr bytes.Buffer
	cmd := exec.Command(bin, keyPath, serverAddr)
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	cmd.Env = append(os.Environ(), "HYDRA_DEBUG=1")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("netns hydra-server stderr:\n%s", stderr.String())
		}
	})
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
	t.Cleanup(stop)
	// The listener is on the host side; a plain host dial to the same IP
	// proves it is up (the netns child reaches it over the router).
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", serverAddr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("netns hydra-server did not listen on %s; stderr:\n%s", serverAddr, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return serverAddr, keyPath, stop
}

// runNetnsChildPass re-executes this test binary inside the client netns for
// one pass (control/disorder) and returns the measured handshake milliseconds.
func runNetnsChildPass(t *testing.T, ns, mode, serverAddr, keyPath string, controlMS int) int {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := []string{
		netnsChildFlagEnv + "=1",
		netnsChildModeEnv + "=" + mode,
		netnsChildAddrEnv + "=" + serverAddr,
		netnsChildKeyEnv + "=" + keyPath,
		netnsChildCtrlEnv + "=" + strconv.Itoa(controlMS),
		netnsChildDelayE + "=10",
	}
	args := append([]string{"-n", "env"},
		env...)
	// The child self-terminates via coreutils timeout: killing the sudo
	// wrapper alone cannot reach the netns-held grandchild, which would wedge
	// the lab netns open and poison the next run's setup.
	args = append(args, "ip", "netns", "exec", ns, "timeout", "-k", "2", "70", exe,
		"-test.run=^"+t.Name()+"$", "-test.timeout=60s")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s pass inside %s failed: %v\n%s", mode, ns, err, out)
	}
	return parseSplitResult(t, mode, string(out))
}

func parseSplitResult(t *testing.T, mode, out string) int {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SPLIT_RESULT mode="+mode+" ") {
			continue
		}
		fields := strings.Fields(line)
		for _, f := range fields {
			if v, ok := strings.CutPrefix(f, "ms="); ok {
				ms, err := strconv.Atoi(v)
				if err != nil || ms < 0 {
					t.Fatalf("bad SPLIT_RESULT: %q", line)
				}
				return ms
			}
		}
	}
	t.Fatalf("no SPLIT_RESULT mode=%s in child output:\n%s", mode, out)
	return 0
}

// lockedWriter serializes bytes.Buffer appends between the tcpdump drain
// goroutine and the test's readiness poll / result parser.
type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// startRouterCapture captures the client's TCP data segments on the router's
// client-facing interface while the disorder pass runs. The returned finish
// function stops the capture and yields its tcpdump -n -v output lines for
// findTTLDeath; the capture IS the packet-level death proof, so a missing
// tcpdump fails the test instead of downgrading the evidence.
func startRouterCapture(t *testing.T, ns, iface, clientIP string) (finish func(timeout time.Duration) ([]string, error)) {
	t.Helper()
	exe, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Fatalf("tcpdump unavailable (%v): the packet-level death proof requires it", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// The capture self-terminates after 6s: killing the sudo wrapper alone
	// cannot reach the root-owned tcpdump grandchild inside the netns, and it
	// would hold the output pipe open forever. One handshake never reaches
	// -c 60, so the timeout is the normal exit path.
	cmd := exec.CommandContext(ctx, "sudo", "-n", "ip", "netns", "exec", ns,
		"timeout", "-k", "2", "6",
		exe, "-n", "-v", "-i", iface, "-c", "60", "src host "+clientIP+" and tcp")
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	var bufMu sync.Mutex
	var buf bytes.Buffer
	bufString := func() string {
		bufMu.Lock()
		defer bufMu.Unlock()
		return buf.String()
	}
	// The drain goroutine races the readiness poller and the finish closure
	// on buf; its writes go through the same mutex.
	bufWriter := lockedWriter{mu: &bufMu, b: &buf}
	if err := cmd.Start(); err != nil {
		t.Fatalf("tcpdump start: %v", err)
	}
	t.Cleanup(func() { _ = pw.Close() })
	drainDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(bufWriter, pr)
		close(drainDone)
	}()
	// Wait until the capture is listening before the child dials.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(bufString(), "listening on") {
		if time.Now().After(deadline) {
			cancel()
			<-drainDone
			t.Fatalf("tcpdump never reported listening:\n%s", bufString())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func(timeout time.Duration) ([]string, error) {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(timeout):
			cancel()
			<-done
		}
		_ = pw.Close()
		<-drainDone
		var lines []string
		for _, l := range strings.Split(bufString(), "\n") {
			if strings.TrimSpace(l) != "" {
				lines = append(lines, l)
			}
		}
		return lines, nil
	}
}

// runNetnsChild is the in-netns half of the death-branch test: one transport
// pass against the host-side server, results printed for the parent.
func runNetnsChild(t *testing.T) {
	mode := os.Getenv(netnsChildModeEnv)
	serverAddr := os.Getenv(netnsChildAddrEnv)
	keyPath := os.Getenv(netnsChildKeyEnv)
	delayMS, _ := strconv.Atoi(os.Getenv(netnsChildDelayE))
	if mode == "" || serverAddr == "" || keyPath == "" {
		t.Fatalf("child env incomplete: mode=%q addr=%q key=%q", mode, serverAddr, keyPath)
	}
	keyBytes, err := decodeB64(string(mustRead(t, keyPath)))
	if err != nil || len(keyBytes) != 32 {
		t.Fatalf("bad child key file: %v", err)
	}
	pk, err := x25519Pub(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	var pubkey [32]byte
	copy(pubkey[:], pk)

	params := SplitParams{
		FirstMin: 20, FirstMax: 30, RestMin: 40, RestMax: 80,
		SplitDelayMs: 5, DisorderDelayMs: delayMS,
	}
	controlMS, _ := strconv.Atoi(os.Getenv(netnsChildCtrlEnv))
	if mode == "disorder" {
		params.Disorder = true
	}

	var gotConn net.Conn
	// 10s dial budget: the child runs inside the client netns where a wedged
	// lab must fail the pass, not hang the whole test to its timeout.
	transport := splitDialer{Dialer: ttlDisorderDialer{
		Dialer: plainNetDialer{d: net.Dialer{Timeout: 10 * time.Second}}, Params: params,
	}, Params: params}
	dialFn := func(ctx context.Context) (net.Conn, error) {
		c, err := transport.DialContext(ctx, "tcp", M.ParseSocksaddr(serverAddr))
		if err == nil {
			gotConn = c
		}
		return c, err
	}
	requestURL := url.URL{Scheme: "ws", Host: serverAddr, Path: "/"}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	start := time.Now()
	tun, err := connectTunnel(context.Background(), dialFn, &requestURL, headers, pubkey[:], nil)
	elapsedMS := int(time.Since(start).Milliseconds())
	if err != nil {
		t.Fatalf("%s pass handshake failed after %dms: %v", mode, elapsedMS, err)
	}
	defer tun.Close()

	if mode == "disorder" {
		split, _ := gotConn.(*helloSplitConn)
		dc, _ := split.Conn.(*ttlDisorderConn)
		if split == nil || dc == nil || !dc.Applied() {
			t.Fatalf("disorder not armed: split=%v dc=%v", split != nil, dc != nil)
		}
		if !dc.Restored() {
			t.Fatal("saved TTL must be restored after the first flight")
		}
		// The lost first segment is recovered by DUPACK-driven fast
		// retransmit (the server already holds segments 2..N), so the wall
		// clock may sit only milliseconds above control. The death itself is
		// proven by the parent's tcpdump on the router (findTTLDeath); here
		// we only guard against a wildly degraded lab.
		if delta := elapsedMS - controlMS; delta >= 2000 {
			t.Fatalf("disorder pass degraded the lab: %dms vs control %dms", elapsedMS, controlMS)
		}
	}
	fmt.Printf("SPLIT_RESULT mode=%s ms=%d applied=%d restored=%d\n",
		mode, elapsedMS, boolInt(gotDisorderApplied(gotConn)), boolInt(gotDisorderRestored(gotConn)))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func gotDisorderApplied(c net.Conn) bool {
	split, ok := c.(*helloSplitConn)
	if !ok {
		return false
	}
	dc, ok := split.Conn.(*ttlDisorderConn)
	return ok && dc.Applied()
}

func gotDisorderRestored(c net.Conn) bool {
	split, ok := c.(*helloSplitConn)
	if !ok {
		return false
	}
	dc, ok := split.Conn.(*ttlDisorderConn)
	return ok && dc.Restored()
}
