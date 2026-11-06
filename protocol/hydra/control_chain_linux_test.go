//go:build linux && !android

package hydra

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra/controlclient"
	"github.com/sagernet/sing/common/json/badoption"
)

// TestExternalControlChain uses the production adaptive outbound, including its
// physical dialer, TLS fronting, negotiation and useful-byte verification.
// The dedicated tester owns the external server, onion service and proof origin.
func TestExternalControlChain(t *testing.T) {
	daemon := os.Getenv("HYDRA_CHAIN_DAEMON")
	onion := os.Getenv("HYDRA_CHAIN_ONION")
	offline := os.Getenv("HYDRA_CHAIN_BUNDLED_CATALOGUE")
	if offline == "" && (daemon == "" || onion == "") {
		t.Skip("external control chain not requested")
	}
	started := time.Now()
	soak := time.Minute
	if raw := os.Getenv("HYDRA_CHAIN_SOAK"); raw != "" {
		var err error
		soak, err = time.ParseDuration(raw)
		if err != nil || soak < 0 || soak > 30*time.Minute {
			t.Fatal("invalid HYDRA_CHAIN_SOAK (0..30m)")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute+soak)
	defer cancel()
	rootPub, err := hex.DecodeString(os.Getenv("HYDRA_CHAIN_ROOT_PUBKEY"))
	if err != nil || len(rootPub) != 32 {
		t.Fatal("invalid root pubkey")
	}
	control := "tor-onion"
	var catalogueBytes, sig []byte
	if offline != "" {
		control = "offline-bundled"
		catalogueBytes, err = os.ReadFile(offline)
		if err != nil {
			t.Fatal(err)
		}
		sig, err = os.ReadFile(os.Getenv("HYDRA_CHAIN_BUNDLED_SIG"))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		cfg := controlclient.Config{
			DaemonPath:   daemon,
			SocksAddr:    "127.0.0.1:0",
			DataDir:      filepath.Join(t.TempDir(), "tor-data"),
			ControlOnion: onion,
		}
		if bridgeFile := os.Getenv("HYDRA_CHAIN_BRIDGES_FILE"); bridgeFile != "" {
			ptType := os.Getenv("HYDRA_CHAIN_PT_TYPE")
			if ptType != "webtunnel" && ptType != "obfs4" {
				t.Fatal("HYDRA_CHAIN_PT_TYPE must be webtunnel or obfs4")
			}
			cfg.ExtraArgs = []string{"--pt-type", ptType, "--bridges-file", bridgeFile, "--pt-path", os.Getenv("HYDRA_CHAIN_PT_PATH")}
			control = "tor-" + ptType + "-onion"
		} else if pt := os.Getenv("HYDRA_CHAIN_PT_PATH"); pt != "" {
			cfg.ExtraArgs = []string{"--bridges", "snowflake", "--pt-path", pt}
			control = "tor-snowflake-onion"
		}
		client, err := controlclient.Start(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		bootstrap, stop := context.WithTimeout(ctx, 3*time.Minute)
		defer stop()
		for !client.Ready() {
			select {
			case <-bootstrap.Done():
				t.Fatal("tor bootstrap deadline exceeded")
			case state := <-client.BootstrapStates():
				t.Logf("bootstrap: %+v", state)
			}
		}
		catalogueBytes, err = client.FetchCatalogue(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sig, err = client.FetchPath(ctx, "/catalogue.sig")
		if err != nil {
			t.Fatal(err)
		}
	}
	controlElapsed := time.Since(started)
	sigBytes, err := hex.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(sigBytes) != 64 {
		t.Fatalf("bad signature encoding: %v", err)
	}
	cat, err := LoadAndVerifyCatalogue(catalogueBytes, sigBytes, rootPub, uint64(time.Now().Unix()), 0)
	if err != nil {
		t.Fatalf("catalogue rejected: %v", err)
	}
	candidates, skips, err := CandidatesFromCatalogue(cat, os.Getenv("HYDRA_CHAIN_ASN"))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) == 0 {
		t.Fatalf("no candidates expanded; skips=%v", skips)
	}
	caPEM, err := os.ReadFile(os.Getenv("HYDRA_CHAIN_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid proof CA")
	}
	proof := proofTarget{URL: os.Getenv("HYDRA_CHAIN_PROOF"), Bytes: 131072, TLS: &tls.Config{RootCAs: roots}}
	factory, err := log.New(log.Options{})
	if err != nil {
		t.Fatal(err)
	}
	options := &option.HydraAdaptiveOptions{
		PhysicalInterface: os.Getenv("HYDRA_CHAIN_INTERFACE"),
		Candidates:        candidates,
		ProofURL:          proof.URL,
		ProofBytes:        proof.Bytes,
		AttemptTimeout:    badoption.Duration(15 * time.Second),
		Backoff:           badoption.Duration(time.Second),
		MaxBackoff:        badoption.Duration(5 * time.Second),
		StatePath:         os.Getenv("HYDRA_CHAIN_STATE_PATH"),
		NetworkKey:        os.Getenv("HYDRA_CHAIN_NETWORK_KEY"),
	}
	if options.StatePath != "" {
		if strings.TrimSpace(options.NetworkKey) == "" {
			t.Fatal("HYDRA_CHAIN_NETWORK_KEY required for persistent state")
		}
		options.NetworkKey = fmt.Sprintf("%s:%x:%x", options.NetworkKey, rootPub, sha256.Sum256(catalogueBytes))
	}
	if dns := os.Getenv("HYDRA_CHAIN_DNS"); dns != "" {
		options.PhysicalDNSServers = strings.Split(dns, ",")
	}
	built, err := newAdaptiveOutboundWithDependencies(ctx, nil, factory.Logger(), "external-control-chain", option.HydraOutboundOptions{Adaptive: options}, adaptiveOutboundDependencies{ProofTLS: proof.TLS})
	if err != nil {
		t.Fatalf("production outbound rejected: %v", err)
	}
	o := built.(*Outbound)
	defer o.Close()
	proofs := 0
	var firstReady time.Duration
	var stableStarted time.Time
	defer func() {
		stableFor := time.Duration(0)
		if !stableStarted.IsZero() {
			stableFor = time.Since(stableStarted)
		}
		report, _ := json.Marshal(map[string]any{
			"snapshot":   o.adaptiveSnapshot(),
			"candidates": len(candidates), "skips": skips,
			"first_verified_ms":     firstReady.Milliseconds(),
			"control_ms":            controlElapsed.Milliseconds(),
			"total_elapsed_ms":      time.Since(started).Milliseconds(),
			"stability_observed_ms": stableFor.Milliseconds(),
			"useful_proofs":         proofs, "proof_bytes_each": proof.Bytes,
			"control": control, "onion": onion, "passed": !t.Failed(),
		})
		fmt.Println("HYDRA_CONTROL_CHAIN " + string(report))
	}()
	searchStarted := time.Now()
	searchCtx, stopSearch := context.WithTimeout(ctx, 90*time.Second)
	tunnel, err := o.getTunnel(searchCtx)
	stopSearch()
	if err != nil {
		t.Fatalf("adaptive acquire: %v", err)
	}
	firstReady = time.Since(searchStarted)
	if err = verifyTunnelProof(ctx, tunnel, proof); err != nil {
		t.Fatalf("proof through promoted tunnel: %v", err)
	}
	proofs++
	stableStarted = time.Now()
	deadline := stableStarted.Add(soak)
	for time.Now().Before(deadline) {
		delay := 5 * time.Second
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-tunnel.Done():
			timer.Stop()
			t.Fatal("promoted tunnel died during stability observation")
		case <-timer.C:
		}
		if err = verifyTunnelProof(ctx, tunnel, proof); err != nil {
			t.Fatalf("stability useful proof: %v", err)
		}
		proofs++
	}
	if os.Getenv("HYDRA_CHAIN_RECOVERY") == "" {
		return
	}
	// Recovery phase: the operator kills the winning server during this
	// window; the harness measures death detection -> reacquired verified
	// tunnel. The coordinator rebuilds through the persisted hint or the
	// next epoch candidate; the 30 s RecoveryBudget applies to the epoch.
	fmt.Println("HYDRA_RECOVERY_WINDOW_OPEN", time.Now().UnixMilli())
	killWindow := 90 * time.Second
	killDeadline := time.Now().Add(killWindow)
	diedAt := time.Time{}
	for time.Now().Before(killDeadline) {
		if tunnel.IsDead() {
			diedAt = time.Now()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if diedAt.IsZero() {
		t.Fatal("tunnel was not killed within the recovery window")
	}
	recoverCtx, stopRecover := context.WithTimeout(ctx, 60*time.Second)
	recovered, err := o.getTunnel(recoverCtx)
	stopRecover()
	if err != nil {
		t.Fatalf("recovery acquire: %v", err)
	}
	recoveryMs := time.Since(diedAt)
	if err = verifyTunnelProof(ctx, recovered, proof); err != nil {
		t.Fatalf("recovery proof: %v", err)
	}
	proofs++
	recoveryProofMs := time.Since(diedAt)
	report, _ := json.Marshal(map[string]any{
		"recovery_ms":       recoveryMs.Milliseconds(),
		"recovery_proof_ms": recoveryProofMs.Milliseconds(),
		"within_30s":        recoveryProofMs <= 30*time.Second,
		"snapshot":          o.adaptiveSnapshot(),
		"useful_proofs":     proofs,
	})
	fmt.Println("HYDRA_RECOVERY " + string(report))
}
