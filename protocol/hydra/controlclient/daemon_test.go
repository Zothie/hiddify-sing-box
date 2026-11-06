// Integration tests against the real tor-control-daemon binary in mock mode:
// no live Tor, no network beyond loopback. The daemon is built first with
// cargo (skipped when the manifest/cargo is unavailable; override the binary
// path with TOR_CONTROL_DAEMON_BIN).
package controlclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const defaultDaemonManifest = "/home/varingait/src/hydra-adaptive/hydra/tools/tor-control-daemon/Cargo.toml"

func buildDaemon(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("TOR_CONTROL_DAEMON_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		t.Fatalf("TOR_CONTROL_DAEMON_BIN=%q does not exist", p)
	}
	manifest := os.Getenv("TOR_CONTROL_DAEMON_MANIFEST")
	if manifest == "" {
		manifest = defaultDaemonManifest
	}
	if _, err := os.Stat(manifest); err != nil {
		t.Skipf("tor-control-daemon manifest not found: %s", manifest)
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	cmd := exec.Command("cargo", "build", "--manifest-path", manifest, "--offline")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cargo build failed: %v\n%s", err, out)
	}
	return filepath.Join(filepath.Dir(manifest), "target", "debug", "tor-control-daemon")
}

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "testdata", "catalogue_signed.json"))
	if err != nil {
		t.Fatalf("fixture path: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	return b
}

func waitReady(t *testing.T, c *Client, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c.Ready() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("daemon did not become ready in time")
}

func newMockClient(t *testing.T, daemonPath string, fixturePath string) *Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, err := Start(ctx, Config{
		DaemonPath:   daemonPath,
		SocksAddr:    "127.0.0.1:0",
		DataDir:      t.TempDir(),
		ControlOnion: "hydracontroltest.onion",
		ExtraArgs:    []string{"--mock-file", fixturePath},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	waitReady(t, c, 15*time.Second)
	return c
}

func TestFetchCatalogueReturnsExactFixtureBytes(t *testing.T) {
	daemon := buildDaemon(t)
	fixture := fixtureBytes(t)
	fixturePath := filepath.Join(t.TempDir(), "catalogue_signed.json")
	if err := os.WriteFile(fixturePath, fixture, 0o644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}

	c := newMockClient(t, daemon, fixturePath)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := c.FetchCatalogue(ctx)
	if err != nil {
		t.Fatalf("FetchCatalogue: %v", err)
	}
	if !bytes.Equal(got, fixture) {
		gs, fs := sha256.Sum256(got), sha256.Sum256(fixture)
		t.Fatalf("catalogue not byte-exact: got %d bytes sha256=%s, want %d bytes sha256=%s",
			len(got), hex.EncodeToString(gs[:]), len(fixture), hex.EncodeToString(fs[:]))
	}
}

func TestRestartAfterDaemonKilledMidRun(t *testing.T) {
	daemon := buildDaemon(t)
	fixture := fixtureBytes(t)
	fixturePath := filepath.Join(t.TempDir(), "catalogue_signed.json")
	if err := os.WriteFile(fixturePath, fixture, 0o644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}
	c := newMockClient(t, daemon, fixturePath)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.FetchCatalogue(ctx); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	// Kill the daemon mid-run; the client must see an error, then a bounded
	// restart must bring it back.
	c.mu.Lock()
	cmd := c.cmd
	c.mu.Unlock()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill daemon: %v", err)
	}

	// In-flight/next fetch fails (daemon gone; no clearnet fallback).
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := c.FetchCatalogue(ctx)
		if err == nil && time.Now().Before(deadline) {
			// restart may already have happened; the error window may be
			// missed entirely — acceptable, continue to the ready wait.
			break
		}
		if err != nil {
			t.Logf("fetch error after kill (expected): %v", err)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for the NEW daemon generation (the restart actually happened),
	// not the old process's stale ready flag.
	gDeadline := time.Now().Add(15 * time.Second)
	for c.generation() < 2 {
		if time.Now().After(gDeadline) {
			t.Fatalf("daemon was not restarted (generation=%d)", c.generation())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Bounded restart: ready again, fetch succeeds again.
	waitReady(t, c, 15*time.Second)
	got, err := c.FetchCatalogue(ctx)
	if err != nil {
		t.Fatalf("fetch after restart: %v", err)
	}
	if !bytes.Equal(got, fixture) {
		t.Fatalf("post-restart body not byte-exact (%d vs %d bytes)", len(got), len(fixture))
	}
}

func TestNonLoopbackSocksAddrRefused(t *testing.T) {
	daemon := buildDaemon(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Start(ctx, Config{
		DaemonPath:   daemon,
		SocksAddr:    "10.1.2.3:19100",
		DataDir:      t.TempDir(),
		ControlOnion: "hydracontroltest.onion",
	})
	if err == nil {
		t.Fatal("Start with non-loopback SocksAddr must be refused")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoFallbackWhenDaemonClosed(t *testing.T) {
	daemon := buildDaemon(t)
	fixturePath := filepath.Join(t.TempDir(), "catalogue_signed.json")
	if err := os.WriteFile(fixturePath, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}
	c := newMockClient(t, daemon, fixturePath)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.FetchCatalogue(ctx)
	if err == nil {
		t.Fatal("FetchCatalogue after Close must fail (no direct-net fallback)")
	}
	if !strings.Contains(err.Error(), "daemon not running") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBootstrapStatesStream(t *testing.T) {
	daemon := buildDaemon(t)
	fixturePath := filepath.Join(t.TempDir(), "catalogue_signed.json")
	if err := os.WriteFile(fixturePath, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}
	c := newMockClient(t, daemon, fixturePath)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("no BOOTSTRAP state received")
		case st := <-c.BootstrapStates():
			if st.Ready {
				return // ready state observed through the callback stream
			}
		}
	}
}
