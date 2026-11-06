package hydra

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
)

func proofOrigin(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		body := proofTestBody(nonce, 4096)
		w.Header().Set("X-Hydra-Nonce", nonce)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	t.Cleanup(origin.Close)
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	return origin, roots
}

func dialServer(server string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server)
	}
}

func requestURL(server string) *url.URL {
	return &url.URL{Scheme: "ws", Host: server, Path: "/"}
}

// Integration: real Rust servers behind two adaptive candidates sharing one
// static key. A degraded report must build and verify the alternative in the
// background, promote it without dropping traffic, and close the old tunnel;
// proof must pass through the swapped tunnel.
func TestAdaptivePrewarmIntegration(t *testing.T) {
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	pk, err := x25519Pub(sk)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := t.TempDir() + "/shared.key"
	if err := os.WriteFile(keyPath, []byte(encodeB64(sk)), 0o600); err != nil {
		t.Fatal(err)
	}
	addrA, pubkeyA, _ := startRustServerKeyed(t, keyPath)
	addrB, pubkeyB, _ := startRustServerKeyed(t, keyPath)
	if !bytes.Equal(pubkeyA[:], pk) || !bytes.Equal(pubkeyB[:], pk) {
		t.Fatal("shared-key servers must publish the same pubkey")
	}
	origin, roots := proofOrigin(t)
	proof := func(ctx context.Context, r adaptive.Resource) error {
		return verifyTunnelProof(ctx, r.(*Tunnel), proofTarget{URL: origin.URL, Bytes: 4096, TLS: &tls.Config{RootCAs: roots}})
	}

	controller, err := adaptive.New(context.Background(), adaptive.Config{
		Candidates:     []adaptive.Candidate{{ID: "a"}, {ID: "b"}},
		AttemptTimeout: 8 * time.Second,
		Backoff:        50 * time.Millisecond,
		MaxBackoff:     500 * time.Millisecond,
		Connect: func(ctx context.Context, cnd adaptive.Candidate) (adaptive.Resource, error) {
			server := addrA
			if cnd.ID == "b" {
				server = addrB
			}
			return connectTunnel(ctx, dialServer(server), requestURL(server), http.Header{}, pk[:], nil)
		},
		Verify: func(ctx context.Context, _ adaptive.Candidate, r adaptive.Resource) error {
			return proof(ctx, r)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tunnelA, err := controller.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if controller.Snapshot().ActiveID != "a" {
		t.Fatalf("unexpected first candidate: %+v", controller.Snapshot())
	}
	if err := proof(ctx, tunnelA); err != nil {
		t.Fatalf("proof through first tunnel: %v", err)
	}

	controller.ReportDegraded()
	deadline := time.Now().Add(15 * time.Second)
	for controller.Snapshot().ActiveID != "b" {
		if time.Now().After(deadline) {
			t.Fatalf("alternative never promoted: %+v", controller.Snapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
	tunnelB, err := controller.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tunnelB == tunnelA {
		t.Fatal("swap reused the degraded tunnel object")
	}
	if err := proof(ctx, tunnelB); err != nil {
		t.Fatalf("proof through swapped tunnel: %v", err)
	}
	select {
	case <-tunnelA.Done():
	default:
		t.Fatal("degraded tunnel was not closed after the swap")
	}
	fmt.Fprintln(os.Stderr) // keep imports honest when servers stay quiet
}

// Degradation with a dead alternative endpoint must leave the healthy tunnel
// serving and its proof passing.
func TestAdaptivePrewarmKeepsActiveOnDeadAlternative(t *testing.T) {
	addrA, pubkeyA, _ := startRustServer(t)
	origin, roots := proofOrigin(t)
	proof := func(ctx context.Context, r adaptive.Resource) error {
		return verifyTunnelProof(ctx, r.(*Tunnel), proofTarget{URL: origin.URL, Bytes: 4096, TLS: &tls.Config{RootCAs: roots}})
	}
	controller, err := adaptive.New(context.Background(), adaptive.Config{
		Candidates:     []adaptive.Candidate{{ID: "a"}, {ID: "dead-port"}},
		AttemptTimeout: 2 * time.Second,
		Backoff:        50 * time.Millisecond,
		MaxBackoff:     500 * time.Millisecond,
		Connect: func(ctx context.Context, cnd adaptive.Candidate) (adaptive.Resource, error) {
			server := addrA
			if cnd.ID != "a" {
				server = "127.0.0.1:1" // nothing listens here
			}
			return connectTunnel(ctx, dialServer(server), requestURL(server), http.Header{}, pubkeyA[:], nil)
		},
		Verify: func(ctx context.Context, _ adaptive.Candidate, r adaptive.Resource) error {
			return proof(ctx, r)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tunnelA, err := controller.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	controller.ReportDegraded()
	time.Sleep(3 * time.Second)
	if controller.Snapshot().ActiveID != "a" {
		t.Fatalf("active replaced by a dead endpoint: %+v", controller.Snapshot())
	}
	if err := proof(ctx, tunnelA); err != nil {
		t.Fatalf("healthy tunnel must keep proving after a failed alternative: %v", err)
	}
}
