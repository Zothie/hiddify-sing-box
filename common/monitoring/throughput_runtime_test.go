package monitoring

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

type localDialer struct{}

func (localDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, destination.String())
}

func (localDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// startFreezer runs a server that completes the HTTP exchange and then stops
// forwarding after freezeAt bytes, imitating the censor's behaviour. If
// freezeAt is negative the full body is delivered.
func startFreezer(t *testing.T, freezeAt int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	total := 128 * 1024
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Content-Length", "131072")
			w.WriteHeader(http.StatusOK)
			n := total
			if freezeAt >= 0 {
				n = freezeAt
			}
			w.Write(make([]byte, n))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if freezeAt >= 0 {
				// Hold the connection open and send nothing further.
				select {
				case <-r.Context().Done():
				case <-time.After(10 * time.Second):
				}
			}
		}),
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String() + "/probe"
}

// TestProbePolicyEvictsFrozenNodeEndToEnd drives the real probe policy -- the
// same code path the monitor uses -- against a genuinely frozen server and a
// genuinely healthy one, and asserts the verdicts differ.
//
// This is the end-to-end version of the whole premise: both nodes pass the
// latency probe, only one passes the data-carrying probe.
func TestProbePolicyEvictsFrozenNodeEndToEnd(t *testing.T) {
	frozenURL := startFreezer(t, 16*1024)
	healthyURL := startFreezer(t, -1)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Both nodes look healthy to the latency probe.
	for name, u := range map[string]string{"frozen": frozenURL, "healthy": healthyURL} {
		delay, err := urltest.URLTest(ctx, u, localDialer{})
		if err != nil {
			t.Fatalf("%s: latency probe unexpectedly failed: %v", name, err)
		}
		t.Logf("latency probe: %s node reports %dms (looks healthy)", name, delay)
	}

	frozenProbe := newThroughputProbe(&option.ThroughputProbeOptions{
		URL:       frozenURL,
		Timeout:   badoption.Duration(15 * time.Second),
		MaxJitter: badoption.Duration(10 * time.Millisecond),
	})
	healthyProbe := newThroughputProbe(&option.ThroughputProbeOptions{
		URL:       healthyURL,
		Timeout:   badoption.Duration(15 * time.Second),
		MaxJitter: badoption.Duration(10 * time.Millisecond),
	})

	fr, frozenPassed, _ := frozenProbe.run(ctx, stubOutbound{})
	hr, healthyPassed, err := healthyProbe.run(ctx, stubOutbound{})
	if err != nil {
		t.Fatalf("healthy probe errored: %v", err)
	}

	t.Logf("throughput probe: frozen  carried %6d bytes -> passed=%v", fr.CarriedBytes, frozenPassed)
	t.Logf("throughput probe: healthy carried %6d bytes -> passed=%v", hr.CarriedBytes, healthyPassed)

	if frozenPassed {
		t.Fatalf("frozen node passed the probe, carrying %d bytes", fr.CarriedBytes)
	}
	if !healthyPassed {
		t.Fatalf("healthy node failed the probe, carrying only %d bytes", hr.CarriedBytes)
	}

	// A failed node must then be suppressed, so we do not hammer a path the
	// censor has penalised.
	now := time.Now()
	frozenProbe.noteResult("frozen", frozenPassed, now)
	if !frozenProbe.suppressed("frozen", now.Add(time.Second)) {
		t.Fatal("frozen node should be in backoff after failing")
	}
}

// stubOutbound adapts a plain local dialer to the adapter.Outbound the probe
// expects; only DialContext is exercised.
type stubOutbound struct {
	adapter.Outbound
}

func (stubOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return localDialer{}.DialContext(ctx, network, destination)
}
