package hydra

// REAL scale integration: five adaptive clients, one shared Rust hydra-server
// process, each client carrying a DISTINCT axis variant, with asynchronous
// config sweeping during a REAL link loss:
//
//	c1 max_frame=16384 (negotiation default frag)
//	c2 max_frame=4096  + ClientHello frag_first 20..30 / rest 40..80 / 5ms,
//	                     armed on the wire through a local TLS front (the
//	                     production dialer chain: base -> disorder -> split
//	                     -> TLS)
//	c3 max_frame=8192  + disorder on (TTL=1 first flight; loopback delivers)
//	c4 max_frame=16384 + pad_buckets [256,512,1024]
//	c5 max_frame=16384 with a candidate PAIR {primA, primB} backed by two
//	                     separate server processes sharing one key
//
// Assertions are timing/byte based and completion-channel driven (no
// sleeps-as-proof): baseline concurrent byte-exact transfers, then c5's
// primary server is SIGKILLed mid-transfer and the test proves
//
//	a) c1..c4 transfers continue and complete byte-exact with zero retries
//	   (server session isolation: the shared server is untouched),
//	b) c5's coordinator sweeps asynchronously to primB inside the 30 s
//	   budget (measured kill -> verified),
//	c) the shared server stays healthy for c1..c4 during c5's loss (a fresh
//	   probe session roundtrips mid-loss on top of continued transfers),
//	d) c5's TotalAttempts stays bounded through the loss window (no tight
//	   loop),
//
// and finally a client-side tunnel reset (ResetNetwork, the public
// generation/reset seam) for c2 mid-transfer proves re-verification on the
// SAME candidate without touching the others.
//
// Skipped when the hydra-server binary is absent (HYDRA_SERVER_BIN).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
)

// scaleServerBinFallback is the negotiate-capable Rust fixture used when the
// harness does not pin HYDRA_SERVER_BIN itself.
const scaleServerBinFallback = "/home/varingait/src/hydra-adaptive/hydra/target-rtc-repro/debug/hydra-server"

const (
	scaleChunkKiB    = 32
	scaleVerifyKiB   = 4096 / 1024 // proof size per Verify (engine enforces 1 KiB..1 MiB)
	scaleSweepBudget = 30 * time.Second
)

// scaleClient is one independent client: its own adaptive coordinator, its
// own tunnel(s) and its own axis variant.
type scaleClient struct {
	name      string
	scheme    string // "ws" (plain) or "wss" (through the local TLS front)
	servers   map[string]string
	pubkey    [32]byte
	maxFrame  uint32
	axes      tunnelAxes
	tlsSplit  SplitParams // armed only when scheme == wss
	relayAddr string      // TLS front target for wss clients
	coord     *adaptive.Coordinator
	echoHost  string
	echoPort  uint16
	begin     time.Time // adaptive.New time, for the verify latency
	firstWait time.Duration

	moved      atomic.Int64 // payload bytes roundtripped byte-exact
	retries    atomic.Int64 // rounds redone after a tunnel death
	progress   atomic.Int64 // in-flight writer position, bytes
	splitConn  atomic.Pointer[helloSplitConn]
	disorderOK atomic.Bool
}

func (cl *scaleClient) dialPlain(addr string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", addr)
	}
}

// dialTLS reproduces the production wss dialer chain order (base TCP ->
// ttlDisorder on the raw socket -> hello splitter -> lazy TLS client), so
// the ClientHello flight really fragments (and, for the disorder variant,
// really leaves with TTL=1) on the wire toward the local TLS front.
func (cl *scaleClient) dialTLS(params SplitParams, relayAddr string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var nd net.Dialer
		c, err := nd.DialContext(ctx, "tcp", relayAddr)
		if err != nil {
			return nil, err
		}
		if params.Disorder {
			if dc, applied := newTTLDisorderConn(c, params); applied {
				c = dc
				cl.disorderOK.Store(true)
			}
		}
		split := newHelloSplitConnParams(c, params)
		cl.splitConn.Store(split)
		return tls.Client(split, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		}), nil
	}
}

// scaleConnect is the production-shaped adaptive Connect: a real negotiated
// tunnel to the candidate's endpoint, with this client's max_frame and axes.
func (cl *scaleClient) scaleConnect(ctx context.Context, cnd adaptive.Candidate) (adaptive.Resource, error) {
	addr, ok := cl.servers[cnd.ID]
	if !ok {
		return nil, fmt.Errorf("%s: unknown candidate %q", cl.name, cnd.ID)
	}
	var dial func(context.Context) (net.Conn, error)
	if cl.scheme == "wss" {
		dial = cl.dialTLS(cl.tlsSplit, cl.relayAddr)
	} else {
		dial = cl.dialPlain(addr)
	}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	requestURL := url.URL{Scheme: cl.scheme, Host: addr, Path: "/"}
	return connectTunnelNegotiate(ctx, dial, &requestURL, headers, cl.pubkey[:], nil, cl.maxFrame, cl.axes)
}

// scaleVerify is the production-shaped adaptive Verify: a useful-byte proof
// fetched THROUGH the candidate tunnel from a local HTTPS origin.
func scaleVerify(originURL string, roots *x509.CertPool) func(context.Context, adaptive.Candidate, adaptive.Resource) error {
	return func(ctx context.Context, _ adaptive.Candidate, r adaptive.Resource) error {
		return verifyTunnelProof(ctx, r.(*Tunnel), proofTarget{URL: originURL, Bytes: scaleVerifyKiB * 1024, TLS: &tls.Config{RootCAs: roots}})
	}
}

// runRound performs one byte-exact echo round through the coordinator. If
// gate is non-nil the round parks after writing half the payload until the
// gate closes, so the transfer provably spans an injected event. Deaths of
// the active tunnel are absorbed by re-acquiring (counted in retries).
func (cl *scaleClient) runRound(ctx context.Context, payload []byte, gate <-chan struct{}, progress func(int64)) error {
	expect := int64(len(payload))
	chunk := scaleChunkKiB * 1024
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s: %w", cl.name, err)
		}
		r, err := cl.coord.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("%s: acquire: %w", cl.name, err)
		}
		tun := r.(*Tunnel)
		s, err := tun.openSession(ctx, cl.echoHost, cl.echoPort)
		if err != nil {
			select {
			case <-tun.Done():
				cl.retries.Add(1)
				continue
			default:
				return fmt.Errorf("%s: open session: %w", cl.name, err)
			}
		}
		gated := false
		writeErr := error(nil)
		for off := 0; off < len(payload) && writeErr == nil; off += chunk {
			end := off + chunk
			if end > len(payload) {
				end = len(payload)
			}
			if _, err := s.Write(payload[off:end]); err != nil {
				writeErr = err
				break
			}
			cl.progress.Store(int64(end))
			if progress != nil {
				progress(int64(end))
			}
			if gate != nil && !gated && int64(end) >= expect/2 {
				gated = true
				select {
				case <-gate:
					// The gate releases after the injected event; from here
					// every remaining op is deadline-bounded so a dead
					// tunnel surfaces as an error, never a hang.
					_ = s.SetDeadline(time.Now().Add(15 * time.Second))
				case <-ctx.Done():
					_ = s.Close()
					return fmt.Errorf("%s: gate: %w", cl.name, ctx.Err())
				}
			}
		}
		if writeErr == nil && !gated {
			_ = s.SetDeadline(time.Now().Add(15 * time.Second))
		}
		if writeErr != nil {
			_ = s.Close()
			select {
			case <-tun.Done():
				cl.retries.Add(1)
				continue
			default:
				return fmt.Errorf("%s: write: %w", cl.name, writeErr)
			}
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(s, got); err != nil {
			_ = s.Close()
			select {
			case <-tun.Done():
				cl.retries.Add(1)
				continue
			default:
				return fmt.Errorf("%s: read: %w", cl.name, err)
			}
		}
		_ = s.Close()
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("%s: round payload mismatch (%d bytes)", cl.name, len(payload))
		}
		cl.moved.Add(expect)
		return nil
	}
}

// startTLSFrontRelay is the local TLS front the wss clients dial: it
// terminates real TLS 1.3 from the client and relays plain bytes to the
// target Rust server, mirroring a wss fronting relay without touching
// production code.
func startTLSFrontRelay(t *testing.T, target string) string {
	t.Helper()
	cert := scaleSelfSignedCert(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var open []net.Conn
	track := func(c net.Conn) {
		mu.Lock()
		open = append(open, c)
		mu.Unlock()
	}
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range open {
			_ = c.Close()
		}
	})
	go func() {
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			track(raw)
			go func(raw net.Conn) {
				tconn := tls.Server(raw, cfg)
				up, err := net.Dial("tcp", target)
				if err != nil {
					_ = tconn.Close()
					return
				}
				track(up)
				go func() {
					_, _ = io.Copy(up, tconn)
					_ = up.Close()
				}()
				_, _ = io.Copy(tconn, up)
				_ = tconn.Close()
				_ = up.Close()
			}(raw)
		}
	}()
	return l.Addr().String()
}

func scaleSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hydra-scale-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// waitInflight blocks until every client has pushed at least threshold bytes
// into its in-flight round (or fails the test on timeout).
func waitInflight(t *testing.T, clients []*scaleClient, threshold int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		all := true
		for _, cl := range clients {
			if cl.progress.Load() < threshold {
				all = false
				break
			}
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			states := ""
			for _, cl := range clients {
				states += fmt.Sprintf(" %s=%d/%d", cl.name, cl.progress.Load(), threshold)
			}
			t.Fatalf("clients never reached in-flight threshold:%s", states)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitSettled blocks until every coordinator has a promoted active resource
// and no search in progress.
func waitSettled(t *testing.T, clients []*scaleClient, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		all := true
		for _, cl := range clients {
			snap := cl.coord.Snapshot()
			if snap.SearchInProgress || snap.ActiveID == "" {
				all = false
				break
			}
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			states := ""
			for _, cl := range clients {
				snap := cl.coord.Snapshot()
				states += fmt.Sprintf(" %s{active=%s search=%v}", cl.name, snap.ActiveID, snap.SearchInProgress)
			}
			t.Fatalf("coordinators never settled within %s:%s", timeout, states)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func scaleRandomPayload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// scaleStartRounds runs one round per client concurrently and returns the
// completion channel (one error-or-nil per client, in client order).
func scaleStartRounds(ctx context.Context, clients []*scaleClient, payloads [][]byte, gate chan struct{}) chan error {
	done := make(chan error, len(clients))
	for i, cl := range clients {
		go func(cl *scaleClient, payload []byte) {
			done <- cl.runRound(ctx, payload, gate, nil)
		}(cl, payloads[i])
	}
	return done
}

// scaleCollectDrains n round completions, failing the test on any error.
func scaleCollect(t *testing.T, done chan error, n int, what string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
}

// TestScaleFiveClientsAsyncSweepLinkLoss runs the whole scale scenario.
func TestScaleFiveClientsAsyncSweepLinkLoss(t *testing.T) {
	if os.Getenv("HYDRA_SERVER_BIN") == "" {
		t.Setenv("HYDRA_SERVER_BIN", scaleServerBinFallback)
	}
	testStart := time.Now()
	rootCtx, rootCancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer rootCancel()

	// One shared static key across ALL server processes: the five clients
	// authenticate against every server with the same pubkey.
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	keyPath := t.TempDir() + "/scale-shared.key"
	if err := os.WriteFile(keyPath, []byte(encodeB64(sk)), 0o600); err != nil {
		t.Fatal(err)
	}
	sharedAddr, pubkey, stopShared := startRustServerKeyed(t, keyPath)
	primAAddr, pubkeyA, stopPrimA := startRustServerKeyed(t, keyPath)
	primBAddr, pubkeyB, stopPrimB := startRustServerKeyed(t, keyPath)
	if !bytes.Equal(pubkeyA[:], pubkey[:]) || !bytes.Equal(pubkeyB[:], pubkey[:]) {
		t.Fatal("shared-key servers must publish the same pubkey")
	}
	defer stopShared()
	defer stopPrimB()
	defer stopPrimA()

	relayAddr := startTLSFrontRelay(t, sharedAddr)
	echoHost, echoPort := splitHostPort(t, startTCPEcho(t))
	origin, roots := proofOrigin(t)

	buildCoord := func(cl *scaleClient, candidates []adaptive.Candidate) {
		cl.begin = time.Now()
		c, err := adaptive.New(context.Background(), adaptive.Config{
			Candidates:     candidates,
			AttemptTimeout: 6 * time.Second,
			Backoff:        50 * time.Millisecond,
			MaxBackoff:     800 * time.Millisecond,
			Connect:        cl.scaleConnect,
			Verify:         scaleVerify(origin.URL, roots),
		})
		if err != nil {
			t.Fatalf("%s: adaptive.New: %v", cl.name, err)
		}
		cl.coord = c
	}

	fragParams := SplitParams{FirstMin: 20, FirstMax: 30, RestMin: 40, RestMax: 80, SplitDelayMs: 5}
	disorderParams := SplitParams{Disorder: true, DisorderDelayMs: 10}
	padCfg := newPadConfig([]uint32{256, 512, 1024}, 0, 0)
	if padCfg == nil {
		t.Fatal("newPadConfig([256,512,1024]) returned nil")
	}

	clients := []*scaleClient{
		{name: "c1-frame16384", scheme: "ws", servers: map[string]string{"c1-frame16384": sharedAddr}, pubkey: pubkey, maxFrame: 16384, echoHost: echoHost, echoPort: echoPort},
		{name: "c2-frag4096", scheme: "wss", servers: map[string]string{"c2-frag4096": sharedAddr}, pubkey: pubkey, maxFrame: 4096, tlsSplit: fragParams, relayAddr: relayAddr, echoHost: echoHost, echoPort: echoPort},
		{name: "c3-disorder8192", scheme: "wss", servers: map[string]string{"c3-disorder8192": sharedAddr}, pubkey: pubkey, maxFrame: 8192, tlsSplit: disorderParams, relayAddr: relayAddr, echoHost: echoHost, echoPort: echoPort},
		{name: "c4-pad16384", scheme: "ws", servers: map[string]string{"c4-pad16384": sharedAddr}, pubkey: pubkey, maxFrame: 16384, axes: tunnelAxes{pad: padCfg}, echoHost: echoHost, echoPort: echoPort},
		{name: "c5-sweep", scheme: "ws", servers: map[string]string{"c5-primA": primAAddr, "c5-primB": primBAddr}, pubkey: pubkey, maxFrame: 16384, echoHost: echoHost, echoPort: echoPort},
	}
	for _, cl := range clients {
		candidates := make([]adaptive.Candidate, 0, len(cl.servers))
		for id := range cl.servers {
			candidates = append(candidates, adaptive.Candidate{ID: id})
		}
		buildCoord(cl, candidates)
		defer cl.coord.Close()
	}
	c1, c2, c3, c4, c5 := clients[0], clients[1], clients[2], clients[3], clients[4]

	// ---- Phase 1: five concurrent verifies against the shared server ----
	// One server must hold five concurrent negotiate sessions with DIFFERENT
	// per-client max_frames plus per-client axes. If it cannot, that is the
	// test's red finding.
	acquireStart := time.Now()
	verifyDone := make(chan error, len(clients))
	for _, cl := range clients {
		go func(cl *scaleClient) {
			ctx, cancel := context.WithTimeout(rootCtx, 20*time.Second)
			defer cancel()
			if _, err := cl.coord.Acquire(ctx); err != nil {
				verifyDone <- fmt.Errorf("%s: initial acquire: %w", cl.name, err)
				return
			}
			cl.firstWait = time.Since(acquireStart)
			verifyDone <- nil
		}(cl)
	}
	for range clients {
		if err := <-verifyDone; err != nil {
			t.Fatal(err)
		}
	}
	for _, cl := range clients {
		want := map[*scaleClient]uint32{c1: 16384, c2: 4096, c3: 8192, c4: 16384, c5: 16384}[cl]
		ctx, cancel := context.WithTimeout(rootCtx, 5*time.Second)
		r, err := cl.coord.Acquire(ctx)
		cancel()
		if err != nil {
			t.Fatalf("%s: re-acquire: %v", cl.name, err)
		}
		tun := r.(*Tunnel)
		if got := tun.NegotiatedMaxFrame(); got != want {
			t.Fatalf("FINDING: %s negotiated max_frame=%d, want %d (status %q): the server did not honor this client's per-connection negotiation", cl.name, got, want, tun.NegotiationStatus())
		}
		if !bytes.HasPrefix([]byte(tun.NegotiationStatus()), []byte("accepted")) {
			t.Fatalf("%s: negotiation status %q, want accepted", cl.name, tun.NegotiationStatus())
		}
		t.Logf("%s: verified in %v, negotiated max_frame=%d (%s)", cl.name, cl.firstWait.Round(time.Millisecond), tun.NegotiatedMaxFrame(), tun.NegotiationStatus())
	}
	if c2.splitConn.Load() == nil || c3.splitConn.Load() == nil {
		t.Fatal("wss clients never armed their hello splitter")
	}
	if !c3.disorderOK.Load() {
		t.Fatal("c3's disorder axis never armed (TTL trick not applied on the raw socket)")
	}
	if got := c2.splitConn.Load().SegmentsWritten(); got < 3 {
		t.Fatalf("c2's first flight fragmented into %d segments, want >=3 (frag 20..30 + rest 40..80)", got)
	}

	// ---- Phase 2: simultaneous 256 KiB baseline transfers, byte-exact ----
	baseline := scaleRandomPayload(t, 256*1024)
	phaseStart := time.Now()
	baselineDone := scaleStartRounds(rootCtx, clients, [][]byte{baseline, baseline, baseline, baseline, baseline}, nil)
	scaleCollect(t, baselineDone, len(clients), "baseline round")
	baselineElapsed := time.Since(phaseStart)
	movedTotal := int64(0)
	for _, cl := range clients {
		if cl.retries.Load() != 0 {
			t.Fatalf("%s: baseline round needed %d retries: cross-client disturbance", cl.name, cl.retries.Load())
		}
		movedTotal += cl.moved.Load()
	}
	waitSettled(t, clients, 10*time.Second)
	t.Logf("baseline: 5 clients x 256KiB byte-exact in %v (total moved %d bytes, 0 retries)", baselineElapsed.Round(time.Millisecond), movedTotal)

	// ---- Phase 3: c5's active candidate's server SIGKILLed mid-transfer ----
	// Whichever endpoint the coordinator currently holds is "the primary"
	// for this run (the first handshake can legitimately land on either
	// candidate); the kill must hit the server behind THAT candidate, and
	// the sweep must land on the survivor.
	lossPayload := scaleRandomPayload(t, 384*1024)
	lossPayloads := [][]byte{scaleRandomPayload(t, 384*1024), scaleRandomPayload(t, 384*1024), scaleRandomPayload(t, 384*1024), scaleRandomPayload(t, 384*1024), lossPayload}
	gate := make(chan struct{})
	c5RetriesAtRoundStart := c5.retries.Load()
	lossDone := scaleStartRounds(rootCtx, clients, lossPayloads, gate)
	waitInflight(t, clients, 384*1024/2)

	snapBefore := c5.coord.Snapshot()
	activeID := snapBefore.ActiveID
	_, isA := c5.servers["c5-primA"]
	_, isB := c5.servers["c5-primB"]
	if !isA || !isB || (activeID != "c5-primA" && activeID != "c5-primB") {
		t.Fatalf("c5 active candidate %q is not one of its two endpoints", activeID)
	}
	otherID := "c5-primB"
	if activeID == "c5-primB" {
		otherID = "c5-primA"
	}
	if d := c5.retries.Load() - c5RetriesAtRoundStart; d != 0 {
		t.Fatalf("c5 tunnel died during round start (retries delta %d): ambiguous kill target", d)
	}
	killServer := map[string]func(){"c5-primA": stopPrimA, "c5-primB": stopPrimB}[activeID]
	killAt := time.Now()
	killServer() // SIGKILL the server process behind c5's active candidate

	// (b) sweep watcher: measure kill -> verified asynchronously. The
	// promotion gate (ActiveID flips to the survivor) is observed first so
	// the watcher can never latch onto the dying resource.
	sweepResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(rootCtx, scaleSweepBudget)
		defer cancel()
		for {
			snap := c5.coord.Snapshot()
			if snap.ActiveID == otherID && !snap.SearchInProgress {
				break
			}
			if ctx.Err() != nil {
				sweepResult <- fmt.Errorf("c5 did not sweep to %s within %s: %w", otherID, scaleSweepBudget, ctx.Err())
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		r, err := c5.coord.Acquire(ctx)
		if err != nil {
			sweepResult <- fmt.Errorf("c5 sweep acquire within %s: %w", scaleSweepBudget, err)
			return
		}
		tun := r.(*Tunnel)
		if tun.NegotiatedMaxFrame() != 16384 {
			sweepResult <- fmt.Errorf("c5 post-sweep negotiated max_frame=%d, want 16384", tun.NegotiatedMaxFrame())
			return
		}
		sweepResult <- nil
	}()

	// (c) shared-server health DURING c5's loss: a fresh probe session on c1
	// must roundtrip while c5 sweeps.
	probePayload := scaleRandomPayload(t, 64*1024)
	probeDone := make(chan error, 1)
	go func() {
		probeDone <- c1.runRound(rootCtx, probePayload, nil, nil)
	}()

	// (a) c1..c4 second halves flow DURING the loss window.
	close(gate)
	for i := 0; i < 4; i++ {
		if err := <-lossDone; err != nil {
			t.Fatalf("c1..c4 transfer across c5's loss: %v", err)
		}
	}
	for _, cl := range clients[:4] {
		if cl.retries.Load() != 0 {
			t.Fatalf("%s: needed %d retries across c5's loss: cross-client disturbance", cl.name, cl.retries.Load())
		}
	}
	if err := <-probeDone; err != nil {
		t.Fatalf("shared-server probe session during c5's loss: %v", err)
	}

	sweepElapsed := time.Since(killAt)
	if err := <-sweepResult; err != nil {
		t.Fatalf("FINDING: %v", err)
	}
	snapAfter := c5.coord.Snapshot()
	if snapAfter.ActiveID != otherID {
		t.Fatalf("c5 active after sweep is %q, want %s", snapAfter.ActiveID, otherID)
	}
	attemptDelta := snapAfter.TotalAttempts - snapBefore.TotalAttempts
	if attemptDelta < 1 {
		t.Fatal("c5 made no sweep attempt after the kill")
	}
	if attemptDelta > 8 {
		t.Fatalf("FINDING: c5 made %d attempts across the loss window: tight-loop sweep", attemptDelta)
	}
	if err := <-lossDone; err != nil {
		t.Fatalf("c5 post-loss round: %v", err)
	}
	if c5.retries.Load() == 0 {
		t.Fatal("c5's in-flight round never observed the loss (no retry recorded)")
	}
	waitSettled(t, clients, 10*time.Second)
	t.Logf("loss: %s server SIGKILLed at +%.0fms; c5 swept to %s and verified in %v (attempts delta %d, per-candidate %v); c1..c4+probe byte-exact during the loss",
		activeID, float64(killAt.Sub(testStart).Microseconds())/1000, otherID, sweepElapsed.Round(time.Millisecond), attemptDelta, snapAfter.PerCandidate)

	// ---- Phase 4: client-side tunnel reset (c2) mid-transfer ----
	resetPayload := scaleRandomPayload(t, 256*1024)
	resetPayloads := [][]byte{resetPayload, resetPayload, resetPayload, resetPayload, resetPayload}
	gate2 := make(chan struct{})
	resetDone := scaleStartRounds(rootCtx, clients, resetPayloads, gate2)
	waitInflight(t, clients, 256*1024/2)

	othersBefore := make([]uint64, 0, 4)
	othersRetriesBefore := make([]int64, 0, 4)
	for _, cl := range []*scaleClient{c1, c3, c4, c5} {
		othersBefore = append(othersBefore, cl.coord.Snapshot().TotalAttempts)
		// Retry counters are cumulative across phases (c5 carries its loss
		// retry); assertions below compare deltas, not absolutes.
		othersRetriesBefore = append(othersRetriesBefore, cl.retries.Load())
	}
	c2GenBefore := c2.coord.Snapshot().Generation
	c2RetriesBefore := c2.retries.Load()

	resetAt := time.Now()
	c2.coord.ResetNetwork() // public seam: kills c2's tunnel, server untouched
	// Re-verify watcher: started AFTER the reset so the elapsed measures the
	// real regeneration, never a pre-reset acquire of the healthy tunnel.
	c2Reverify := make(chan time.Duration, 1)
	go func() {
		ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
		defer cancel()
		for {
			snap := c2.coord.Snapshot()
			if snap.ActiveID == "c2-frag4096" && snap.Generation == c2GenBefore+1 && !snap.SearchInProgress {
				break
			}
			if ctx.Err() != nil {
				c2Reverify <- -1
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		if _, err := c2.coord.Acquire(ctx); err != nil {
			c2Reverify <- -1
			return
		}
		c2Reverify <- time.Since(resetAt)
	}()
	close(gate2)

	for i := 0; i < 4; i++ {
		if err := <-resetDone; err != nil {
			t.Fatalf("other clients across c2's reset: %v", err)
		}
	}
	for i, cl := range []*scaleClient{c1, c3, c4, c5} {
		if d := cl.retries.Load() - othersRetriesBefore[i]; d != 0 {
			t.Fatalf("%s: needed %d retries across c2's reset: cross-client disturbance", cl.name, d)
		}
		delta := cl.coord.Snapshot().TotalAttempts - othersBefore[i]
		if delta != 0 {
			t.Fatalf("%s: made %d attempts during c2's reset: cross-client disturbance", cl.name, delta)
		}
	}
	if err := <-resetDone; err != nil {
		t.Fatalf("c2 post-reset round: %v", err)
	}
	c2ReverifyElapsed := <-c2Reverify
	if c2ReverifyElapsed < 0 {
		t.Fatalf("c2 did not re-verify within 30s of ResetNetwork")
	}
	c2Snap := c2.coord.Snapshot()
	if c2Snap.ActiveID != "c2-frag4096" {
		t.Fatalf("c2 active after reset is %q, want c2-frag4096 (same candidate)", c2Snap.ActiveID)
	}
	if c2Snap.Generation != c2GenBefore+1 {
		t.Fatalf("c2 generation %d, want %d after exactly one ResetNetwork", c2Snap.Generation, c2GenBefore+1)
	}
	if c2.retries.Load() <= c2RetriesBefore {
		t.Fatal("c2's in-flight round never observed the reset (no retry recorded)")
	}
	if got := c2.splitConn.Load().SegmentsWritten(); got < 3 {
		t.Fatalf("c2's re-verified first flight fragmented into %d segments, want >=3", got)
	}
	waitSettled(t, clients, 10*time.Second)

	// The shared server survived everything and still accepts connections.
	if conn, err := net.DialTimeout("tcp", sharedAddr, 2*time.Second); err != nil {
		t.Fatalf("FINDING: shared server died during the scenario: %v", err)
	} else {
		_ = conn.Close()
	}

	total := time.Since(testStart)
	t.Logf("reset: c2 ResetNetwork at +%.0fms re-verified SAME candidate in %v (gen %d, retries %d); others 0 retries 0 attempts delta",
		float64(resetAt.Sub(testStart).Microseconds())/1000, c2ReverifyElapsed.Round(time.Millisecond), c2Snap.Generation, c2.retries.Load())
	for _, cl := range clients {
		t.Logf("final %s: moved %d bytes byte-exact, retries %d", cl.name, cl.moved.Load(), cl.retries.Load())
	}
	if total >= 120*time.Second {
		t.Fatalf("test budget exceeded: %s (want <120s)", total)
	}
	t.Logf("scale scenario complete in %v", total.Round(time.Millisecond))
}
