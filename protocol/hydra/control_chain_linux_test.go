//go:build linux && !android

package hydra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	"github.com/sagernet/sing-box/protocol/hydra/controlclient"
	M "github.com/sagernet/sing/common/metadata"
)

// TestExternalControlChain is opt-in: the dedicated tester provisions the Tor
// daemon (real bootstrap), the onion service serving /catalogue and
// /catalogue.sig, and the proof origin, then sets:
//
//	HYDRA_CHAIN_DAEMON, HYDRA_CHAIN_ONION, HYDRA_CHAIN_ROOT_PUBKEY (hex),
//	HYDRA_CHAIN_ASN, HYDRA_CHAIN_PROOF, HYDRA_CHAIN_CA, HYDRA_CHAIN_INTERFACE
//
// Chain: Tor-only catalogue fetch -> Ed25519 verify -> candidate expansion ->
// adaptive tunnel per catalogue recipe -> useful-byte proof through the
// promoted tunnel. There is no direct-net fallback anywhere on this path.
func TestExternalControlChain(t *testing.T) {
	daemon := os.Getenv("HYDRA_CHAIN_DAEMON")
	onion := os.Getenv("HYDRA_CHAIN_ONION")
	if daemon == "" || onion == "" {
		t.Skip("external control chain not requested")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rootPub, err := hex.DecodeString(os.Getenv("HYDRA_CHAIN_ROOT_PUBKEY"))
	if err != nil || len(rootPub) != 32 {
		t.Fatal("invalid root pubkey")
	}
	client, err := controlclient.Start(ctx, controlclient.Config{
		DaemonPath:   daemon,
		SocksAddr:    "127.0.0.1:19051",
		DataDir:      filepath.Join(t.TempDir(), "tor-data"),
		ControlOnion: onion,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(3 * time.Minute)
	for !client.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("tor bootstrap deadline exceeded")
		}
		select {
		case state := <-client.BootstrapStates():
			t.Logf("bootstrap: %+v", state)
		case <-time.After(time.Second):
		}
	}
	catalogueBytes, err := client.FetchCatalogue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := client.FetchPath(ctx, "/catalogue.sig")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := LoadAndVerifyCatalogue(catalogueBytes, sig, rootPub, uint64(time.Now().Unix()), 0)
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
	proofURL := os.Getenv("HYDRA_CHAIN_PROOF")
	proof := proofTarget{URL: proofURL, Bytes: 131072, TLS: &tls.Config{RootCAs: roots}}
	verifyProof := func(ctx context.Context, r adaptive.Resource) error {
		return verifyTunnelProof(ctx, r.(*Tunnel), proof)
	}
	iface := os.Getenv("HYDRA_CHAIN_INTERFACE")
	physical, physicalErr := newAdaptivePhysicalDialer(ctx, &option.HydraAdaptiveOptions{PhysicalInterface: iface}, option.HydraAdaptiveCandidateOptions{})
	var physicalPin *dialer.PhysicalDialer
	if physicalErr == nil {
		physicalPin, _ = physical.(*dialer.PhysicalDialer)
	}

	factory, logErr := log.New(log.Options{})
	if logErr != nil {
		t.Fatal(logErr)
	}
	logger := factory.Logger()
	recipeByID := make(map[string]CatalogueRecipe)
	for _, recipe := range cat.Recipes {
		recipeByID[recipe.ID] = recipe
	}
	connect := func(ctx context.Context, candidate adaptive.Candidate) (adaptive.Resource, error) {
		recipe, ok := recipeByID[candidate.ID]
		if !ok {
			return nil, fmt.Errorf("recipe %s vanished", candidate.ID)
		}
		serverPub, err := ServerPubkey(cat, candidate.ID)
		if err != nil {
			return nil, err
		}
		endpoint := firstWssEndpoint(cat, recipe.Server)
		if endpoint == nil {
			return nil, fmt.Errorf("recipe %s has no wss endpoint", candidate.ID)
		}
		maxFrame, _ := RecipeMaxFrame(cat, candidate.ID)
		requestURL := &url.URL{Scheme: "ws", Host: endpoint.Host, Path: endpoint.Path}
		if endpoint.SNI != "" {
			requestURL.Host = endpoint.SNI
		}
		switch recipe.Transport {
		case "rtc":
			ip, err := resolveHost(endpoint.Host)
			if err != nil {
				return nil, err
			}
			addrPort := netip.AddrPortFrom(ip, endpoint.Port)
			return connectTunnelRTC(ctx, packetDialFrom(ctx, physicalPin, addrPort), serverPub, addrPort, logger, maxFrame)
		default:
			return connectTunnelNegotiate(ctx, plainDial(physicalPin, endpoint.Host, endpoint.Port), requestURL, http.Header{}, serverPub, logger, maxFrame)
		}
	}
	candidateIDs := make([]adaptive.Candidate, 0, len(candidates))
	for i := range candidates {
		candidateIDs = append(candidateIDs, adaptive.Candidate{ID: candidates[i].ID})
	}
	controller, err := adaptive.New(ctx, adaptive.Config{
		Candidates:     candidateIDs,
		AttemptTimeout: 15 * time.Second,
		Backoff:        500 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
		Connect:        connect,
		Verify: func(ctx context.Context, _ adaptive.Candidate, r adaptive.Resource) error {
			return verifyProof(ctx, r)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	tunnel, err := controller.Acquire(ctx)
	if err != nil {
		t.Fatalf("adaptive acquire: %v", err)
	}
	if err := verifyProof(ctx, tunnel); err != nil {
		t.Fatalf("proof through promoted tunnel: %v", err)
	}
	snapshot := controller.Snapshot()
	report, _ := json.Marshal(map[string]any{
		"active":     snapshot.ActiveID,
		"attempts":   snapshot.Attempts,
		"candidates": len(candidates),
		"skips":      skips,
		"proof":      "integrity-ok-131072",
		"onion":      onion,
	})
	fmt.Println("HYDRA_CONTROL_CHAIN " + string(report))
}

// firstWssEndpoint returns the first wss endpoint of a server, nil when none.
func firstWssEndpoint(cat *Catalogue, serverID string) *CatalogueEndpoint {
	for i := range cat.Servers {
		if cat.Servers[i].ID != serverID {
			continue
		}
		for j := range cat.Servers[i].Endpoints {
			if cat.Servers[i].Endpoints[j].Transport == "wss" {
				return &cat.Servers[i].Endpoints[j]
			}
		}
	}
	return nil
}

// resolveHost accepts literals and falls back to the system resolver; the
// stand catalogue carries literal IPs.
func resolveHost(host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	addr, ok := netip.AddrFromSlice(ips[0])
	if !ok {
		return netip.Addr{}, fmt.Errorf("resolve %s: unusable address", host)
	}
	return addr.Unmap(), nil
}

// packetDialFrom builds the rtc UDP socket dialer; a nil physical dialer uses
// the default UDP path. The peer is known at dial time, so the physical
// dialer can validate and pin the route.
func packetDialFrom(ctx context.Context, physical *dialer.PhysicalDialer, peer netip.AddrPort) rtcPacketDial {
	return func(dialCtx context.Context) (net.PacketConn, error) {
		if physical != nil {
			return physical.ListenPacket(dialCtx, M.ParseSocksaddr(peer.String()))
		}
		var lc net.ListenConfig
		return lc.ListenPacket(dialCtx, "udp", "0.0.0.0:0")
	}
}

// plainDial returns a TCP dial func; a configured physical dialer takes
// precedence over the default path.
func plainDial(physical *dialer.PhysicalDialer, host string, port uint16) func(context.Context) (net.Conn, error) {
	return func(dialCtx context.Context) (net.Conn, error) {
		if physical != nil {
			return physical.DialContext(dialCtx, "tcp", M.ParseSocksaddr(net.JoinHostPort(host, fmt.Sprint(port))))
		}
		var d net.Dialer
		return d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	}
}
