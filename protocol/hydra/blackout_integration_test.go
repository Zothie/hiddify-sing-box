package hydra

// Blackout edge case: when every reference probe fails, the physical internet
// is dead, so the adaptive sweep must stop entirely and recheck slowly; when a
// reference answers, the sweep resumes and a real tunnel verifies. Real Rust
// server, real HTTPS origin, real coordinator — no fakes.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

// blackoutOrigin is a TLS origin whose port and certificate identity survive
// restarts: a blackout recheck must recover against the same origin, not a
// regenerated one.
type blackoutOrigin struct {
	addr   string
	url    string
	cert   tls.Certificate
	roots  *x509.CertPool
	server *http.Server
}

func newBlackoutOrigin(t *testing.T) *blackoutOrigin {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "blackout-origin"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &blackoutOrigin{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots: roots}
	o.addr = listener.Addr().String()
	o.url = "https://" + o.addr
	_ = listener.Close()
	t.Cleanup(o.down)
	if err := o.up(); err != nil {
		t.Fatal(err)
	}
	return o
}

func (o *blackoutOrigin) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		body := proofTestBody(nonce, 4096)
		w.Header().Set("X-Hydra-Nonce", nonce)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
	return mux
}

func (o *blackoutOrigin) up() error {
	listener, err := net.Listen("tcp", o.addr)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: o.handler()}
	o.server = server
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{o.cert}}))
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 300 * time.Millisecond}, "tcp", o.addr, &tls.Config{RootCAs: o.roots})
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("origin did not come up on %s: %w", o.addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (o *blackoutOrigin) down() {
	if o.server != nil {
		_ = o.server.Close()
		o.server = nil
	}
}

// startRustServerKeyedOn spawns the real hydra-server binary on a FIXED
// address with a shared key file, so a candidate endpoint can be dead during
// one phase and alive in the next.
func startRustServerKeyedOn(t *testing.T, addr, keyPath string) (stop func()) {
	t.Helper()
	bin := os.Getenv("HYDRA_SERVER_BIN")
	if bin == "" {
		bin = defaultServerBin
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("hydra-server binary not present (%s): %v", bin, err)
	}
	var stderr bytes.Buffer
	cmd := exec.Command(bin, keyPath, addr)
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
	var mu sync.Mutex
	stop = func() {
		mu.Lock()
		defer mu.Unlock()
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return stop
		}
		if time.Now().After(deadline) {
			t.Fatalf("hydra-server did not listen on %s; stderr:\n%s", addr, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAdaptiveBlackoutIntegration(t *testing.T) {
	origin := newBlackoutOrigin(t)
	deadPort := freePort(t)
	deadAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(deadPort))
	sk := make([]byte, 32)
	if _, err := cryptorand.Read(sk); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(keyPath, []byte(encodeB64(sk)), 0o600); err != nil {
		t.Fatal(err)
	}
	pk, err := x25519Pub(sk)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(deadAddr)
	port, _ := strconv.Atoi(portText)
	candidate := func(id, path string) option.HydraAdaptiveCandidateOptions {
		return option.HydraAdaptiveCandidateOptions{ID: id, ServerOptions: option.ServerOptions{Server: host, ServerPort: uint16(port)}, Path: path}
	}
	opts := option.HydraOutboundOptions{Pubkey: encodeB64(pk[:]), Adaptive: &option.HydraAdaptiveOptions{
		Candidates:      []option.HydraAdaptiveCandidateOptions{candidate("dead-a", "/a"), candidate("dead-b", "/b")},
		ProofURL:        origin.url + "/proof",
		ProofBytes:      4096,
		AttemptTimeout:  badoption.Duration(300 * time.Millisecond),
		Backoff:         badoption.Duration(20 * time.Millisecond),
		MaxBackoff:      badoption.Duration(40 * time.Millisecond),
		ReferenceURLs:   []string{origin.url + "/ref1", origin.url + "/ref2"},
		BlackoutRecheck: badoption.Duration(30 * time.Second),
	}}
	out, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "blackout", opts, adaptiveOutboundDependencies{
		ProofTLS:        &tls.Config{RootCAs: origin.roots},
		ReferenceDialer: func() N.Dialer { d, _ := dialer.New(t.Context(), option.DialerOptions{}, false); return d }(),
		DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
			return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := out.(*Outbound)
	defer o.Close()
	// A real client holds a pending acquire; this also wakes the coordinator's
	// run loop so the sweep actually starts. It stays blocked while the tunnel
	// is dead and returns at the phase 3 promotion.
	acquireCtx, cancelAcquire := context.WithCancel(t.Context())
	defer cancelAcquire()
	go func() { _, _ = o.getTunnel(acquireCtx) }()

	// Phase 1: origin alive — every full dead epoch probes the reference and
	// succeeds, so the sweep keeps going and blackout never engages.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if s := o.adaptiveSnapshot(); s.TotalAttempts >= 4 {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("phase 1 sweep stalled: %+v", s)
		} else {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if s := o.adaptiveSnapshot(); s.Blackout || s.UniqueCandidatesTried != 2 {
		t.Fatalf("alive reference wrongly reported blackout or unfair sweep: %+v", s)
	}

	// Phase 2: kill the origin. The next full dead epoch probes, fails, and
	// the sweep must go FLAT: blackout stops candidate attempts entirely.
	origin.down()
	deadline = time.Now().Add(10 * time.Second)
	for {
		if o.adaptiveSnapshot().Blackout {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("blackout never engaged after origin death: %+v", o.adaptiveSnapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(700 * time.Millisecond) // drain the in-flight attempt epoch
	before := o.adaptiveSnapshot()
	if before.BlackoutReason == "" {
		t.Fatalf("blackout without reason: %+v", before)
	}
	time.Sleep(1500 * time.Millisecond)
	after := o.adaptiveSnapshot()
	if !after.Blackout || after.TotalAttempts != before.TotalAttempts {
		t.Fatalf("sweep not flat under blackout: before=%d after=%d blackout=%v reason=%q", before.TotalAttempts, after.TotalAttempts, after.Blackout, after.BlackoutReason)
	}
	if after.SearchInProgress {
		t.Fatalf("blackout counted as active search: %+v", after)
	}
	t.Logf("blackout flat: attempts=%d reason=%q", before.TotalAttempts, before.BlackoutReason)

	// Phase 3: restart the origin and bring a real Rust server up on the dead
	// endpoint. The next slow recheck clears blackout, the sweep resumes and a
	// real tunnel verifies through the HTTPS proof.
	if err := origin.up(); err != nil {
		t.Fatal(err)
	}
	stopRust := startRustServerKeyedOn(t, deadAddr, keyPath)
	defer stopRust()
	deadline = time.Now().Add(50 * time.Second)
	for {
		if s := o.adaptiveSnapshot(); !s.Blackout && s.ActiveID != "" {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("blackout never cleared or tunnel never verified: %+v", s)
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := o.getTunnel(ctx); err != nil {
		t.Fatalf("resumed tunnel did not verify: %v", err)
	}
}

// Construction-level validation of the blackout configuration, exercising the
// real build path.
func TestAdaptiveBlackoutValidation(t *testing.T) {
	for _, name := range []string{"too-many", "plain-http", "empty-host", "onion", "bad-port", "recheck-low", "recheck-high", "insecure-tls", "user-info"} {
		t.Run(name, func(t *testing.T) {
			a := &option.HydraAdaptiveOptions{
				Candidates: []option.HydraAdaptiveCandidateOptions{{ID: "a", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}}},
				ProofURL:   "https://example.com/proof",
				ProofBytes: 1024,
			}
			deps := adaptiveOutboundDependencies{DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
				return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
			}}
			switch name {
			case "too-many":
				a.ReferenceURLs = []string{"https://a.example", "https://b.example", "https://c.example", "https://d.example"}
			case "plain-http":
				a.ReferenceURLs = []string{"http://example.com"}
			case "empty-host":
				a.ReferenceURLs = []string{"https://"}
			case "onion":
				a.ReferenceURLs = []string{"https://abcdefghijklmnopqrstuvwxyz234567.onion"}
			case "bad-port":
				a.ReferenceURLs = []string{"https://example.com:notaport"}
			case "recheck-low":
				a.ReferenceURLs = []string{"https://example.com"}
				a.BlackoutRecheck = badoption.Duration(29 * time.Second)
			case "recheck-high":
				a.ReferenceURLs = []string{"https://example.com"}
				a.BlackoutRecheck = badoption.Duration(11 * time.Minute)
			case "insecure-tls":
				a.ReferenceURLs = []string{"https://example.com"}
				deps.ProofTLS = &tls.Config{InsecureSkipVerify: true}
			case "user-info":
				a.ReferenceURLs = []string{"https://user:pass@example.com"}
			}
			opts := option.HydraOutboundOptions{Pubkey: encodeB64(make([]byte, 32)), Adaptive: a}
			if o, err := newAdaptiveOutboundWithDependencies(t.Context(), nil, nil, "test", opts, deps); err == nil {
				_ = o.(*Outbound).Close()
				t.Fatal("invalid blackout configuration accepted")
			}
		})
	}
}
