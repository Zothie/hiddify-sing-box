package hydra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
)

// Each phase is an independent executable process. Rust and HTTPS remain real
// across both lifetimes; a loaded hint must still complete a fresh proof.
func TestRecoveryPersistenceIntegration(t *testing.T) {
	addr, pk, _ := startRustServer(t)
	origin, _ := proofOrigin(t)
	path := t.TempDir() + "/winner.json"
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}))
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"seed", "restore"} {
		cmd := exec.Command(exe, "-test.run=^TestRecoveryPersistenceChild$", "-test.v")
		cmd.Env = append(os.Environ(), "HYDRA_PERSIST_CHILD="+phase, "HYDRA_PERSIST_PATH="+path, "HYDRA_PERSIST_ADDR="+addr, "HYDRA_PERSIST_PK="+encodeB64(pk[:]), "HYDRA_PERSIST_ORIGIN="+origin.URL, "HYDRA_PERSIST_CERT="+cert)
		out, err := cmd.CombinedOutput()
		t.Logf("%s: %s", phase, out)
		if err != nil {
			t.Fatalf("child %s: %v", phase, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode %v", info.Mode())
	}
}

func TestRecoveryPersistenceChild(t *testing.T) {
	phase := os.Getenv("HYDRA_PERSIST_CHILD")
	if phase == "" {
		t.Skip("executable helper")
	}
	pk, err := decodeB64(os.Getenv("HYDRA_PERSIST_PK"))
	if err != nil {
		t.Fatal(err)
	}
	addr := os.Getenv("HYDRA_PERSIST_ADDR")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(os.Getenv("HYDRA_PERSIST_CERT"))) {
		t.Fatal("invalid origin certificate")
	}
	var attempts []string
	proofs := 0
	cfg := adaptive.Config{
		StatePath: os.Getenv("HYDRA_PERSIST_PATH"), StateKey: "validated-config-network-v1",
		Candidates:     []adaptive.Candidate{{ID: "dead"}, {ID: "winner"}},
		AttemptTimeout: 3 * time.Second, Backoff: 20 * time.Millisecond, MaxBackoff: 40 * time.Millisecond,
		Connect: func(ctx context.Context, c adaptive.Candidate) (adaptive.Resource, error) {
			attempts = append(attempts, c.ID)
			server := addr
			if c.ID == "dead" {
				server = "127.0.0.1:1"
			}
			return connectTunnel(ctx, dialServer(server), requestURL(server), http.Header{}, pk, nil)
		},
		Verify: func(ctx context.Context, _ adaptive.Candidate, r adaptive.Resource) error {
			// Trust is restricted to the parent test origin, not supplied by state.
			err := verifyTunnelProof(ctx, r.(*Tunnel), proofTarget{URL: os.Getenv("HYDRA_PERSIST_ORIGIN"), Bytes: 4096, TLS: &tls.Config{RootCAs: roots}})
			if err == nil {
				proofs++
			}
			return err
		},
	}
	if phase == "restore" {
		cfg.StateKey = "validated-config-network-v2"
	}
	c, err := adaptive.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err = c.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	want := uint64(2)
	if phase == "restore" {
		want = 1
		if !s.StateLoaded || attempts[0] != "winner" {
			t.Fatalf("winner not restored: %+v attempts=%v", s, attempts)
		}
	}
	if proofs != 1 || s.Attempts != want || s.TotalAttempts != want || s.UniqueCandidatesTried != want || !s.StateSaved || s.StateError != "" || s.SearchElapsed <= 0 || s.SearchInProgress {
		t.Fatalf("bad verified metrics: %+v proofs=%d", s, proofs)
	}
	c.ReportDegraded()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s = c.Snapshot()
		if s.Attempts == want+1 && !s.SearchInProgress {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("prewarm not counted: %+v", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.UniqueCandidatesTried != 2 || s.LastSearchElapsed <= 0 {
		t.Fatalf("prewarm metrics: %+v", s)
	}
	elapsed := s.SearchElapsed
	time.Sleep(50 * time.Millisecond)
	if c.Snapshot().SearchElapsed != elapsed {
		t.Fatal("healthy uptime counted as search")
	}
	old, err := c.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.ResetNetwork()
	if _, err = c.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	s = c.Snapshot()
	if s.StateLoaded || proofs != 2 || s.Attempts <= want+1 || s.LastSearchElapsed <= 0 || s.SearchInProgress {
		t.Fatalf("recovery lacked useful revalidation: %+v proofs=%d", s, proofs)
	}
	select {
	case <-old.Done():
	default:
		t.Fatal("reset kept old tunnel")
	}
	if s.StateSaved || s.StateError != "adaptive state: network changed; recreate coordinator with current network key to persist" {
		t.Fatalf("reset retained persistence: %+v", s)
	}
	if _, e := os.Stat(cfg.StatePath); !os.IsNotExist(e) {
		t.Fatalf("stale winner exists after recovery: %v", e)
	}
	_ = c.Close()
	cfg.StateKey = "validated-config-network-v2"
	fresh, e := adaptive.New(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = fresh.Acquire(ctx); e != nil {
		fresh.Close()
		t.Fatal(e)
	}
	fs := fresh.Snapshot()
	fresh.Close()
	if !fs.StateSaved || fs.StateLoaded || fs.StateError != "" || proofs != 3 {
		t.Fatalf("fresh network failed persistence/revalidation: %+v proofs=%d", fs, proofs)
	}
	data, e := os.ReadFile(cfg.StatePath)
	if e != nil {
		t.Fatal(e)
	}
	var hint struct {
		Key string `json:"key"`
	}
	if e = json.Unmarshal(data, &hint); e != nil || hint.Key != cfg.StateKey {
		t.Fatalf("fresh network key not saved: %s error=%v", data, e)
	}
	cfg.StateKey = "validated-config-network-v1"
	for _, mode := range []string{"malformed", "unwritable", "wrong-key", "unknown-candidate"} {
		cfg.StatePath = t.TempDir() + "/state"
		switch mode {
		case "malformed":
			err = os.WriteFile(cfg.StatePath, []byte("{"), 0600)
		case "unwritable":
			cfg.StatePath += "/missing/state"
		case "wrong-key":
			err = os.WriteFile(cfg.StatePath, []byte(`{"version":1,"key":"other-network","last_good":"winner"}`), 0600)
		case "unknown-candidate":
			err = os.WriteFile(cfg.StatePath, []byte(`{"version":1,"key":"validated-config-network-v1","last_good":"invented"}`), 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		x, e := adaptive.New(context.Background(), cfg)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = x.Acquire(ctx); e != nil {
			x.Close()
			t.Fatal(e)
		}
		xs := x.Snapshot()
		x.Close()
		if xs.StateLoaded || xs.Attempts != 2 {
			t.Fatalf("untrusted hint used (%s): %+v", mode, xs)
		}
		if mode != "wrong-key" && xs.StateError == "" {
			t.Fatalf("missing visible state error (%s): %+v", mode, xs)
		}
		if mode == "unwritable" && xs.StateSaved {
			t.Fatal("unwritable state reported saved")
		}
	}
	b, _ := json.Marshal(s)
	fmt.Printf("verified phase=%s proofs=%d attempts=%v snapshot=%s\n", phase, proofs, attempts, b)
}
