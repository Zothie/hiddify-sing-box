package hydra

// Integration tests for session negotiation (frame types 8/9/10, negotiate.go):
// the golden wire vectors from hydra/tests/negotiate.rs, the legacy-server
// fallback (a server that ignores the unknown type), and the REJECT path —
// all driven through the real FrameStream dispatch both directions.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	ws "github.com/sagernet/ws"
)

// Golden vectors printed by hydra tests/negotiate.rs::export_negotiate_vectors.
const (
	goldenNegotiate = "080100010001000400000800"       // offer MAX_FRAME=2048
	goldenAccept    = "0900010001000400000800"         // accepted MAX_FRAME=2048
	goldenReject    = "0a0d756e6b6e6f776e207461672032" // reason "unknown tag 2"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// startRustServerLogged spawns hydra-server and exposes its stderr (the
// HYDRA_DEBUG=1 per-frame dispatch log) to the test.
func startRustServerLogged(t *testing.T) (serverAddr string, pubkey [32]byte, stderr *bytes.Buffer, stop func()) {
	t.Helper()
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(keyPath, []byte(encodeB64(sk)), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := os.Getenv("HYDRA_SERVER_BIN")
	if bin == "" {
		bin = defaultServerBin
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("hydra-server binary not present (%s): %v", bin, err)
	}
	skDec, err := decodeB64(string(mustRead(t, keyPath)))
	if err != nil || len(skDec) != 32 {
		t.Fatalf("bad key: %v", err)
	}
	pk, err := x25519Pub(skDec)
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	serverAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	var buf bytes.Buffer
	cmd := exec.Command(bin, keyPath, serverAddr)
	cmd.Stderr = &buf
	cmd.Stdout = &buf
	cmd.Env = append(os.Environ(), "HYDRA_DEBUG=1")
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
			// Cmd.Wait (not Process.Wait) also drains exec's stderr copy
			// goroutine, so the buffer is safe to read afterwards.
			_ = cmd.Wait()
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
			t.Fatalf("hydra-server did not listen on %s; stderr:\n%s", serverAddr, buf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	var kp [32]byte
	copy(kp[:], pk)
	return serverAddr, kp, &buf, stop
}

// recordConn records the byte length of every write crossing the transport
// (one sealed AEAD frame per ws binary message), so the test can observe the
// actual on-the-wire frame sizes the client produces.
type recordConn struct {
	net.Conn
	mu     sync.Mutex
	writes []int
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, len(b))
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recordConn) snapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.writes...)
}

// connectNegotiateTunnelCapture is connectTestTunnel with a negotiated
// max_frame and an optional transport write recorder.
func connectNegotiateTunnelCapture(t *testing.T, serverAddr string, pubkey [32]byte, maxFrame uint32, rec *recordConn) *Tunnel {
	t.Helper()
	nd := &net.Dialer{Timeout: handshakeTimeout}
	dialFn := func(ctx context.Context) (net.Conn, error) {
		c, err := nd.DialContext(ctx, "tcp", serverAddr)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			rec.Conn = c
			c = rec
		}
		return c, nil
	}
	requestURL := url.URL{Scheme: "ws", Host: serverAddr, Path: "/"}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	tun, err := connectTunnelNegotiate(context.Background(), dialFn, &requestURL, headers, pubkey[:], nil, maxFrame)
	if err != nil {
		t.Fatalf("connectTunnelNegotiate: %v", err)
	}
	return tun
}

func connectOfferTunnel(t *testing.T, serverAddr string, pubkey [32]byte, offer []byte) *Tunnel {
	t.Helper()
	nd := &net.Dialer{Timeout: handshakeTimeout}
	dialFn := func(ctx context.Context) (net.Conn, error) {
		return nd.DialContext(ctx, "tcp", serverAddr)
	}
	requestURL := url.URL{Scheme: "ws", Host: serverAddr, Path: "/"}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	tun, err := connectTunnelOffer(context.Background(), dialFn, &requestURL, headers, pubkey[:], nil, offer)
	if err != nil {
		t.Fatalf("connectTunnelOffer: %v", err)
	}
	return tun
}

// scanDispatch extracts per-frame counts from the Rust server's
// "hydra-srv dispatch: type=N len=M" stderr lines (inbound frames only).
func scanDispatch(s string) (count2, count8, max2 int) {
	for _, line := range strings.Split(s, "\n") {
		var typ, l int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "hydra-srv dispatch: type=%d len=%d", &typ, &l); err != nil {
			continue
		}
		switch typ {
		case 2:
			count2++
			if l > max2 {
				max2 = l
			}
		case 8:
			count8++
		}
	}
	return
}

// TestNegotiateGoldenVectors: the three golden wire vectors, then a live
// negotiation against the REAL Rust server with a 40000-byte session write
// proven clamped to the negotiated max_frame on the wire (client-side
// transport recorder + the server's own HYDRA_DEBUG dispatch log) with the
// echo roundtrip intact.
func TestNegotiateGoldenVectors(t *testing.T) {
	// Client-built offer must be byte-exact with the Rust golden vector —
	// this exact frame is what the client puts on the wire below.
	if got := hex.EncodeToString(buildNegotiate(2048)); got != goldenNegotiate {
		t.Fatalf("buildNegotiate(2048) = %s, want %s", got, goldenNegotiate)
	}
	for _, bad := range []uint32{0, 1023, 65537, 1 << 30} {
		if buildNegotiate(bad) != nil {
			t.Fatalf("buildNegotiate(%d) must reject out-of-range values", bad)
		}
	}
	// Golden ACCEPT parses through the same code path the tunnel uses.
	acc, err := parseAccept(mustDecodeHex(t, goldenAccept))
	if err != nil || acc.maxFrame != 2048 {
		t.Fatalf("parseAccept(golden) = %+v, %v; want max_frame 2048", acc, err)
	}
	// Golden REJECT: bytes -> reason, and the builder reproduces the bytes.
	if r, err := parseReject(mustDecodeHex(t, goldenReject)); err != nil || r != "unknown tag 2" {
		t.Fatalf("parseReject(golden) = %q, %v; want %q", r, err, "unknown tag 2")
	}
	if got := hex.EncodeToString(buildReject("unknown tag 2")); got != goldenReject {
		t.Fatalf("buildReject = %s, want %s", got, goldenReject)
	}

	serverAddr, pubkey, stderr, stopServer := startRustServerLogged(t)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	rec := &recordConn{}
	tun := connectNegotiateTunnelCapture(t, serverAddr, pubkey, 2048, rec)
	defer tun.Close()

	if got := tun.NegotiatedMaxFrame(); got != 2048 {
		t.Fatalf("real server ACCEPT must apply max_frame=2048, got %d (status %q)", got, tun.NegotiationStatus())
	}

	// A 40000-byte session write must leave as DATA frames clamped to the
	// negotiated cap (2031 payload + AEAD/padding overhead) and echo intact.
	payload := make([]byte, 40000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	s, err := tun.openSession(t.Context(), echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	roundtrip(t, s, payload)
	_ = s.Close()

	// Client-side wire observation: every ws write must fit a 2048 frame
	// (max sealed size = 4 len + 12 nonce + 16 tag + 2 padLen + 64 pad + 2048).
	wireMax := 4 + 12 + 16 + 2 + 64 + 2048
	big := 0
	for _, n := range rec.snapshot() {
		if n > wireMax {
			t.Fatalf("client wrote %d bytes on the wire > %d: negotiated 2048 not honored", n, wireMax)
		}
		if n > 300 {
			big++
		}
	}
	if big < 20 { // ceil(40000 / 2031)
		t.Fatalf("expected >=20 clamped DATA writes, got %d", big)
	}

	// Server-side observation: stop the server (flushes the stderr pipe) and
	// read the real Rust dispatch log — the type-8 offer must have arrived
	// and every type-2 DATA frame must sit within the negotiated frame.
	stopServer()
	count2, count8, max2 := scanDispatch(stderr.String())
	if count8 == 0 {
		t.Fatalf("server never dispatched the NEGOTIATE offer; stderr:\n%s", stderr.String())
	}
	if count2 < 20 || max2 > 2048 {
		t.Fatalf("server saw %d DATA frames (max len %d); want >=20 frames of len <=2048; stderr:\n%s",
			count2, max2, stderr.String())
	}
	t.Logf("rust dispatch: type=8 x%d (offer), type=2 x%d clamped DATA (max len %d)", count8, count2, max2)
}

// TestNegotiateLegacyServerFallsBack: a live ws server that performs the real
// handshake but silently drops the type-8 offer (the legacy dispatch
// fall-through) — the client must fall back to legacy within the (shortened)
// deadline and keep roundtripping.
func TestNegotiateLegacyServerFallsBack(t *testing.T) {
	old := negotiateReplyTimeout
	negotiateReplyTimeout = 300 * time.Millisecond
	defer func() { negotiateReplyTimeout = old }()

	serverAddr, pubkey := startLegacyHydraServer(t)
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	tun := connectNegotiateTunnelCapture(t, serverAddr, pubkey, 2048, nil)
	defer tun.Close()

	if got := tun.NegotiatedMaxFrame(); got != 0 {
		t.Fatalf("legacy fallback must leave max_frame 0, got %d", got)
	}
	if st := tun.NegotiationStatus(); !strings.Contains(st, "legacy fallback") {
		t.Fatalf("status = %q, want the timeout legacy fallback", st)
	}
	s, err := tun.openSession(t.Context(), echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open after fallback: %v", err)
	}
	payload := make([]byte, 8192)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundtrip(t, s, payload)
	_ = s.Close()
}

// TestNegotiateRejectPath: offer the non-whitelisted tag 2 through the same
// live Rust server — it answers the golden REJECT, the tunnel stays usable
// in legacy chunking mode.
func TestNegotiateRejectPath(t *testing.T) {
	serverAddr, pubkey, _, stopServer := startRustServerLogged(t)
	defer stopServer()
	echoAddr, echoPort := splitHostPort(t, startTCPEcho(t))

	// [8][ver=1][count=1][tag=2][len=4][value 0]: tag 2 is not whitelisted,
	// negotiate.rs reject_reason yields exactly "unknown tag 2".
	bad := []byte{8, 1, 0, 1, 0, 2, 0, 4, 0, 0, 0, 0}
	tun := connectOfferTunnel(t, serverAddr, pubkey, bad)
	defer tun.Close()

	if got := tun.NegotiatedMaxFrame(); got != 0 {
		t.Fatalf("rejected negotiation must stay legacy, got max_frame %d", got)
	}
	if st := tun.NegotiationStatus(); st != "rejected: unknown tag 2" {
		t.Fatalf("status = %q, want %q", st, "rejected: unknown tag 2")
	}
	s, err := tun.openSession(t.Context(), echoAddr, echoPort)
	if err != nil {
		t.Fatalf("open after reject: %v", err)
	}
	payload := make([]byte, 8192)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundtrip(t, s, payload)
	_ = s.Close()
}

// ---------------------------------------------------------------------------
// Minimal in-process LEGACY hydra ws server: real HTTP upgrade + real hydra
// handshake + OPEN/DATA/CLOSE relay, but type 8 is dropped (a server build
// from before negotiation). Only what the fallback test needs.
// ---------------------------------------------------------------------------

func startLegacyHydraServer(t *testing.T) (addr string, pubkey [32]byte) {
	t.Helper()
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	pk, err := x25519Pub(sk)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var kp [32]byte
	copy(kp[:], pk)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serveLegacyConn(c, sk, kp)
		}
	}()
	return l.Addr().String(), kp
}

// bufioConn lets the ws layer keep reading bytes the HTTP header scan already
// pulled out of the socket.
type bufioConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufioConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func serveLegacyConn(raw net.Conn, staticSk []byte, staticPk [32]byte) {
	defer raw.Close()
	// 1. Minimal RFC 6455 upgrade handshake (net/http hijack equivalent).
	br := bufio.NewReader(raw)
	key := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Sec-WebSocket-Key") {
			key = strings.TrimSpace(v)
		}
	}
	if key == "" {
		return
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"
	if _, err := raw.Write([]byte(resp)); err != nil {
		return
	}
	wsConn := v2raywebsocket.NewConn(&bufioConn{Conn: raw, r: br}, nil, ws.StateServerSide)

	// 2. hydra handshake, the server side of connectTunnel.
	readBuf := make([]byte, 65536)
	n, err := wsConn.Read(readBuf) // HELLO [u32 len][salt16][seal(...)]
	if err != nil || n < 4+16+53 {
		fmt.Println("LEGACYDBG hello read", n, err)
		return
	}
	frame := readBuf[:n]
	helloLen := binary.BigEndian.Uint32(frame[:4])
	if int(helloLen) != len(frame)-4 {
		fmt.Println("LEGACYDBG hello len", helloLen, len(frame))
		return
	}
	helloCipher, err := kdfHello(staticPk[:], frame[4:20])
	if err != nil {
		fmt.Println("LEGACYDBG kdfhello", err)
		return
	}
	inner, err := openCtr(helloCipher, 0, frame[20:])
	if err != nil || len(inner) != 5+32 || !bytes.Equal(inner[:5], Magic[:]) {
		return
	}
	clientEph := inner[5:37]
	ephSk := make([]byte, 32)
	if _, err = rand.Read(ephSk); err != nil {
		return
	}
	ephPub, err := x25519Pub(ephSk)
	if err != nil {
		return
	}
	salt2 := make([]byte, SaltSize)
	if _, err = rand.Read(salt2); err != nil {
		return
	}
	sharedEph, err := x25519(ephSk, clientEph)
	if err != nil {
		return
	}
	sharedStatic, err := x25519(staticSk, clientEph)
	if err != nil {
		return
	}
	// The AEAD cipher binds the CLIENT's hello salt (the reply salt is
	// transport noise the client ignores).
	transcript := append(append(make([]byte, 0, 64), clientEph...), ephPub...)
	cipher, err := kdfAuth(sharedEph, sharedStatic, frame[4:20], transcript)
	if err != nil {
		return
	}
	reply := make([]byte, 0, 4+5+32+16)
	reply = binary.BigEndian.AppendUint32(reply, uint32(5+32+16))
	reply = append(reply, Magic[:]...)
	reply = append(reply, ephPub...)
	reply = append(reply, salt2...)
	if _, err = wsConn.Write(reply); err != nil {
		return
	}
	if _, err = wsConn.Write(sealCtr(cipher, 1, []byte("hydra-confirm"))); err != nil {
		return
	}

	// 3. Frame pump: LEGACY dispatch — unknown types (8) fall through.
	var srvMu sync.Mutex
	srvCtr := uint64(1)
	srvSend := func(plain []byte) bool {
		srvMu.Lock()
		defer srvMu.Unlock()
		srvCtr++ // CONFIRM consumed 1; data frames continue at 2
		_, err := wsConn.Write(sealCtr(cipher, srvCtr, plain))
		return err == nil
	}
	var sessMu sync.Mutex
	sessions := make(map[[IDSize]byte]net.Conn)
	closeUp := func(id [IDSize]byte) {
		sessMu.Lock()
		up := sessions[id]
		delete(sessions, id)
		sessMu.Unlock()
		if up != nil {
			up.Close()
			srvSend(append([]byte{4}, id[:]...))
		}
	}
	fs := newFrameStream(cipher, 1)
	for {
		n, err := wsConn.Read(readBuf)
		if err != nil {
			return
		}
		frames, err := fs.feed(readBuf[:n])
		if err != nil {
			return
		}
		for _, plain := range frames {
			if len(plain) == 0 {
				continue
			}
			var id [IDSize]byte
			switch plain[0] {
			case 8:
				// legacy server: negotiation offer silently ignored
			case 0: // OPEN [0][id16][hlen][host][port]
				if len(plain) < 20 {
					continue
				}
				copy(id[:], plain[1:17])
				hl := int(plain[17])
				if len(plain) < 20+hl {
					continue
				}
				host := string(plain[18 : 18+hl])
				port := binary.BigEndian.Uint16(plain[18+hl:])
				up, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
				r := append([]byte{3}, id[:]...)
				if err != nil {
					r = append(r, 0)
					srvSend(r)
					continue
				}
				r = append(r, 1)
				if !srvSend(r) {
					up.Close()
					continue
				}
				sessMu.Lock()
				sessions[id] = up
				sessMu.Unlock()
				go func(id [IDSize]byte, up net.Conn) {
					defer func() {
						sessMu.Lock()
						if sessions[id] == up {
							delete(sessions, id)
						}
						sessMu.Unlock()
						up.Close()
					}()
					buf := make([]byte, legacyDataChunk)
					for {
						_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
						n, err := up.Read(buf)
						if n > 0 {
							f := append([]byte{2}, id[:]...)
							f = append(f, buf[:n]...)
							if !srvSend(f) {
								return
							}
						}
						if err != nil {
							return
						}
					}
				}(id, up)
			case 2: // DATA [2][id16]
				if len(plain) < 17 {
					continue
				}
				copy(id[:], plain[1:17])
				sessMu.Lock()
				up := sessions[id]
				sessMu.Unlock()
				if up != nil {
					_, _ = up.Write(plain[17:])
				}
			case 1, 4: // CLOSE (client->server 1 / server->client 4 shape)
				if len(plain) < 17 {
					continue
				}
				copy(id[:], plain[1:17])
				closeUp(id)
			case 7: // HALF-CLOSE [7][id16]
				if len(plain) < 17 {
					continue
				}
				copy(id[:], plain[1:17])
				sessMu.Lock()
				up := sessions[id]
				sessMu.Unlock()
				if tc, ok := up.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}
		}
	}
}
