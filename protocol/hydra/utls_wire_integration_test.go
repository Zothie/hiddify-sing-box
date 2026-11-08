//go:build with_utls

package hydra

// GAP 5 wire test: a uTLS-fingerprinted wss handshake against a REAL Rust
// hydra-server over loopback. Chain: Go static outbound (tls_fingerprint=
// chrome) -> local TLS front (self-signed, terminates TLS, pipes plaintext
// to the Rust ws server) -> hydra-server. The tunnel handshake completes and
// a full proof verification passes THROUGH the tunnel, proving the uTLS
// ClientHello did not disturb the hydra protocol layer.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func startTLSFront(t *testing.T, target string) string {
	t.Helper()
	cert := scaleSelfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				tlsConn := tls.Server(raw, tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					raw.Close()
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					tlsConn.Close()
					return
				}
				go io.Copy(up, tlsConn)
				io.Copy(tlsConn, up)
				tlsConn.Close()
				up.Close()
			}(raw)
		}
	}()
	return l.Addr().String()
}

func TestUTLSFingerprintedTunnelRustServer(t *testing.T) {
	serverAddr, pubkey, _, stop := startRustServerLogged(t)
	defer stop()
	front := startTLSFront(t, serverAddr)
	echo := startTCPEcho(t)

	host, portStr, _ := net.SplitHostPort(front)
	port64, _ := strconv.ParseUint(portStr, 10, 16)
	port := uint16(port64)
	opts := option.HydraOutboundOptions{
		ServerOptions:  option.ServerOptions{Server: host, ServerPort: port},
		Pubkey:         encodeB64(pubkey[:]),
		Transport:      "wss",
		Path:           "/",
		TLSFingerprint: "chrome",
		TLS:            &option.OutboundTLSOptions{Enabled: true, ServerName: "localhost"},
	}
	out, err := newStaticOutbound(t.Context(), nil, "utls-wire", opts, nil)
	if err != nil {
		t.Fatal("static outbound construction (with_utls build):", err)
	}
	o := out.(*Outbound)
	defer o.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	tun, err := o.getTunnel(ctx)
	if err != nil {
		t.Fatalf("uTLS-fingerprinted tunnel handshake failed: %v", err)
	}

	// Proof verification THROUGH the fingerprinted tunnel: fetch a known
	// body over the tunnel's session plane from an HTTPS origin.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		body := proofTestBody(nonce, 1024)
		w.Header().Set("X-Hydra-Nonce", nonce)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}))
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	pctx, pcancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer pcancel()
	if err := verifyTunnelProof(pctx, tun, proofTarget{URL: origin.URL, Bytes: 1024, TLS: &tls.Config{RootCAs: roots}}); err != nil {
		t.Fatalf("proof through uTLS tunnel failed: %v", err)
	}

	// A real session roundtrip: open a session through the tunnel to the
	// echo target (scale-test pattern; the outbound-level DialContext needs
	// a full adapter context).
	echoHost, echoPortStr, _ := net.SplitHostPort(echo)
	echoPort64, _ := strconv.ParseUint(echoPortStr, 10, 16)
	conn, err := tun.openSession(ctx, echoHost, uint16(echoPort64))
	if err != nil {
		t.Fatalf("session open through uTLS tunnel failed: %v", err)
	}
	defer conn.Close()
	msg := []byte("utls-wire-roundtrip")
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo roundtrip through uTLS tunnel failed: %v", err)
	}
	for i := range msg {
		if buf[i] != msg[i] {
			t.Fatalf("echo mismatch: %q", buf)
		}
	}
}
