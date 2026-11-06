//go:build linux && !android

package hydra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	M "github.com/sagernet/sing/common/metadata"
)

// TestExternalAdaptiveBench is opt-in: it never modifies routes or services.
// The dedicated tester starts the server and origin before invoking this binary.
func TestExternalAdaptiveBench(t *testing.T) {
	server := os.Getenv("HYDRA_BENCH_SERVER")
	if server == "" {
		t.Skip("dedicated external stand not requested")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	physical, err := dialer.NewPhysical(ctx, dialer.PhysicalOptions{Interface: os.Getenv("HYDRA_BENCH_INTERFACE")})
	if err != nil {
		t.Fatal(err)
	}
	key, err := decodeB64(os.Getenv("HYDRA_BENCH_PUBKEY"))
	if err != nil || len(key) != 32 {
		t.Fatal("invalid public server key")
	}
	ca, err := os.ReadFile(os.Getenv("HYDRA_BENCH_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid proof CA")
	}
	proof := proofTarget{URL: os.Getenv("HYDRA_BENCH_PROOF"), Bytes: 131072, TLS: &tls.Config{RootCAs: roots}}
	var mu sync.Mutex
	var attempts []string
	controller, err := adaptive.New(ctx, adaptive.Config{
		Candidates:     []adaptive.Candidate{{ID: "must-reject-loopback"}, {ID: "physical-server"}},
		AttemptTimeout: 8 * time.Second, Backoff: 100 * time.Millisecond, MaxBackoff: time.Second,
		Connect: func(attemptCtx context.Context, candidate adaptive.Candidate) (adaptive.Resource, error) {
			mu.Lock()
			attempts = append(attempts, candidate.ID)
			mu.Unlock()
			address := server
			if candidate.ID == "must-reject-loopback" {
				address = "127.0.0.1:45180"
			}
			requestURL := &url.URL{Scheme: "ws", Host: address, Path: "/"}
			tunnel, err := connectTunnel(attemptCtx, func(dialCtx context.Context) (net.Conn, error) {
				return physical.DialContext(dialCtx, "tcp", M.ParseSocksaddr(address))
			}, requestURL, http.Header{}, key, nil)
			if err != nil {
				// Plain nil, never a typed nil: the coordinator closes failed attempts.
				return nil, err
			}
			return tunnel, nil
		},
		Verify: func(attemptCtx context.Context, _ adaptive.Candidate, resource adaptive.Resource) error {
			return verifyTunnelProof(attemptCtx, resource.(*Tunnel), proof)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	start := time.Now()
	first, err := controller.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if controller.Snapshot().ActiveID != "physical-server" {
		t.Fatal("invalid candidate was promoted")
	}
	if err := verifyTunnelProof(ctx, first.(*Tunnel), proof); err != nil {
		t.Fatal(err)
	}
	firstReady := time.Since(start)
	_ = first.Close() // Owned test fault: no system service or other user affected.
	recoveryStart := time.Now()
	second, err := controller.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("dead tunnel was reused")
	}
	if err := verifyTunnelProof(ctx, second.(*Tunnel), proof); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	copyAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(copyAttempts) < 3 || copyAttempts[0] != "must-reject-loopback" || copyAttempts[1] != "physical-server" {
		t.Fatalf("unexpected search sequence: %v", copyAttempts)
	}
	report, err := json.Marshal(map[string]any{
		"server": server, "interface": os.Getenv("HYDRA_BENCH_INTERFACE"),
		"first_ready_ms": firstReady.Milliseconds(), "recovery_ms": time.Since(recoveryStart).Milliseconds(),
		"proof_bytes_per_request": proof.Bytes, "integrity": true, "attempts": copyAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("HYDRA_ADAPTIVE_BENCH " + string(report))
}
