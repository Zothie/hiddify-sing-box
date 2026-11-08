package hydra

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// rawNetDialer adapts the stdlib dialer onto the sing N.Dialer interface.
type rawNetDialer struct{ d net.Dialer }

func (r rawNetDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return r.d.DialContext(ctx, network, destination.String())
}

func (r rawNetDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", destination.String())
}

func option_CandidateWithFingerprint(fp string) option.HydraAdaptiveCandidateOptions {
	return option.HydraAdaptiveCandidateOptions{TLSFingerprint: fp}
}

func testTLSOptions() *option.OutboundTLSOptions {
	return &option.OutboundTLSOptions{Enabled: true, ServerName: "hydra.test"}
}

func startEchoListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l
}

// GAP 5 (tls_fingerprint): closed whitelist, fail-closed unknown names.
func TestValidateTLSFingerprint(t *testing.T) {
	for _, name := range []string{
		"", "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
		"random", "randomized", "chrome_psk", "chrome_psk_shuffle",
		"chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk",
	} {
		if err := validateTLSFingerprint(name); err != nil {
			t.Fatalf("fingerprint %q must be accepted: %v", name, err)
		}
	}
	for _, name := range []string{"Chrome", "curl", "nordvpn", "chrome_psk_bogus"} {
		if err := validateTLSFingerprint(name); err == nil {
			t.Fatalf("unknown fingerprint %q must fail construction", name)
		}
	}
}

func TestResolveCandidateAxesFingerprintFailClosed(t *testing.T) {
	o := option_CandidateWithFingerprint("chrome")
	if _, _, err := axesOrDefault(o, option.HydraAdaptiveCandidateOptions{}, nil); err != nil {
		t.Fatal("chrome must pass:", err)
	}
	bad := option_CandidateWithFingerprint("bogus")
	if _, _, err := axesOrDefault(bad, option.HydraAdaptiveCandidateOptions{}, nil); err == nil {
		t.Fatal("unknown fingerprint must fail candidate resolution")
	}
	// Parent (solo link) axis also fails closed.
	parent := option_CandidateWithFingerprint("bogus")
	if _, _, err := axesOrDefault(option.HydraAdaptiveCandidateOptions{}, parent, nil); err == nil {
		t.Fatal("unknown PARENT fingerprint must fail resolution")
	}
}

func TestApplyTLSAxesFingerprint(t *testing.T) {
	base := testTLSOptions()
	out := applyTLSAxes(base, false, "", "", nil, "firefox")
	if out.UTLS == nil || !out.UTLS.Enabled || out.UTLS.Fingerprint != "firefox" {
		t.Fatalf("fingerprint axis must enable uTLS: %+v", out.UTLS)
	}
	if out == base {
		t.Fatal("caller-owned TLS options must not be mutated")
	}
	untouched := applyTLSAxes(base, false, "", "", nil, "")
	if untouched.UTLS != nil {
		t.Fatalf("empty fingerprint must keep plain TLS: %+v", untouched.UTLS)
	}
	// A pre-existing explicit utls block wins (never silently replaced).
	pre := testTLSOptions()
	pre.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "ios"}
	if out := applyTLSAxes(pre, false, "", "", nil, "chrome"); out.UTLS.Fingerprint != "ios" {
		t.Fatalf("explicit utls must win: %+v", out.UTLS)
	}
}

// GAP 6 (handshake_spacing_ms): the gate serializes handshakes to the SAME
// host with the jittered spacing, and different hosts stay independent.
// Real loopback TCP dials are used as the transport plane; the gate keys are
// non-loopback test hosts (loopback itself bypasses the gate).
func TestSNIGateSpacingRealDials(t *testing.T) {
	l1 := startEchoListener(t)
	l2 := startEchoListener(t)
	gate := newSNIGate()
	dialer := net.Dialer{}
	type dialResult struct {
		start, end time.Time
		err        error
	}
	dialThrough := func(host string) <-chan dialResult {
		ch := make(chan dialResult, 1)
		wrapped := sniSpacingDialer{Dialer: rawNetDialer{d: dialer}, gate: gate, host: host,
			spacing: 100 * time.Millisecond}
		go func() {
			start := time.Now()
			c, err := wrapped.DialContext(context.Background(), "tcp", M.ParseSocksaddr(l1.Addr().String()))
			end := time.Now()
			if err == nil {
				c.Close()
			}
			ch <- dialResult{start, end, err}
		}()
		return ch
	}
	r1 := <-dialThrough("hydra-one.test")
	if r1.err != nil {
		t.Fatal("first dial must pass immediately:", r1.err)
	}
	_ = l2 // second listener proves the transport plane exists; the gate key is the host, not the port
	r2 := <-dialThrough("hydra-one.test")
	if r2.err != nil {
		t.Fatal("second dial must eventually succeed:", r2.err)
	}
	// Wire-level evidence: the second handshake's dial CALL blocks inside
	// DialContext for the jittered spacing (>= 100ms floor), and its grant
	// lands >= 100ms after the first.
	if blocked := r2.end.Sub(r2.start); blocked < 90*time.Millisecond {
		t.Fatalf("same-host second dial must block for the spacing, returned after %v", blocked)
	}
	if gap := r2.end.Sub(r1.start); gap < 100*time.Millisecond {
		t.Fatalf("same-host grants must be spaced >= 100ms, got %v", gap)
	}
	// A different host key is not serialized behind the first host.
	done := make(chan time.Time, 1)
	wrapped := sniSpacingDialer{Dialer: rawNetDialer{d: dialer}, gate: gate, host: "hydra-two.test",
		spacing: 100 * time.Millisecond}
	go func() {
		c, err := wrapped.DialContext(context.Background(), "tcp", M.ParseSocksaddr(l2.Addr().String()))
		if err == nil {
			c.Close()
		}
		done <- time.Now()
	}()
	select {
	case at := <-done:
		if time.Since(at) > 50*time.Millisecond {
			t.Fatal("different host must not wait behind the first")
		}
	case <-time.After(time.Second):
		t.Fatal("different-host dial stalled")
	}
}

func TestClampHandshakeSpacing(t *testing.T) {
	cases := []struct {
		in   uint32
		want time.Duration
	}{
		{0, 2000 * time.Millisecond},  // default band 2-4s with jitter
		{50, 100 * time.Millisecond},  // below min clamps
		{100, 100 * time.Millisecond}, // min honored
		{5000, 5000 * time.Millisecond},
		{70000, 60000 * time.Millisecond}, // above max clamps
	}
	for _, c := range cases {
		if got := clampHandshakeSpacing(c.in); got != c.want {
			t.Fatalf("clamp(%d) = %v, want %v", c.in, got, c.want)
		}
	}
	// Loopback bypass: the effective spacing is zero on loopback hosts.
	if got := effectiveSpacing("127.0.0.1", 0); got != 0 {
		t.Fatalf("loopback must bypass the gate, got %v", got)
	}
	if got := effectiveSpacing("example.com", 0); got != 2*time.Second {
		t.Fatalf("public host default must be 2s, got %v", got)
	}
}

// Catalogue param vocabulary: tls_fingerprint + handshake_spacing_ms.
func TestCatalogueTLSFingerprintAndSpacingParams(t *testing.T) {
	ax, err := parseRecipeAxes(map[string]any{
		"tls_fingerprint":      "chrome",
		"handshake_spacing_ms": float64(50),
	})
	if err != nil {
		t.Fatal("valid params must parse:", err)
	}
	if ax.tlsFingerprint != "chrome" {
		t.Fatalf("fingerprint param lost: %q", ax.tlsFingerprint)
	}
	if ax.spacingMs != 100 {
		t.Fatalf("spacing below min must clamp to 100, got %d", ax.spacingMs)
	}
	ax, err = parseRecipeAxes(map[string]any{"handshake_spacing_ms": float64(70000)})
	if err != nil {
		t.Fatal(err)
	}
	if ax.spacingMs != 60000 {
		t.Fatalf("spacing above max must clamp to 60000, got %d", ax.spacingMs)
	}
	if _, err := parseRecipeAxes(map[string]any{"tls_fingerprint": "bogus"}); err == nil {
		t.Fatal("unknown catalogue fingerprint must fail the recipe (fail-closed)")
	}
}
