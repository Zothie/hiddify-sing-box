package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// directDialer is a minimal N.Dialer that just dials locally, so these tests
// exercise the probe itself rather than any proxy protocol.
type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, destination.String())
}

func (directDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// TestFrozenServerFailsProbeButPassesLatencyProbe is the end-to-end proof of the
// whole design. It stands up a server that behaves exactly like a TSPU-frozen
// path: the TCP connection is accepted, TLS completes, HTTP headers come back
// 200 OK, and then forwarding stops partway through the body -- here after
// 16 KB, the low end of the reported 16-20 KB freeze threshold.
//
// The ordinary latency probe (HEAD, no body) sees a perfectly healthy server.
// The throughput probe must see the truth.
func TestFrozenServerFailsProbeButPassesLatencyProbe(t *testing.T) {
	const freezeAt = 16 * 1024

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			// A HEAD carries no body, so the freeze is invisible here. This is
			// precisely why latency probing cannot detect this failure.
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", "131072")
		w.WriteHeader(http.StatusOK)
		w.Write(make([]byte, freezeAt))
		w.(http.Flusher).Flush()
		// ...and now stop forwarding, holding the connection open.
		time.Sleep(3 * time.Second)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The latency probe is fooled: it reports success.
	delay, err := URLTest(ctx, server.URL, directDialer{})
	if err != nil {
		t.Fatalf("latency probe should succeed against a frozen node, got %v", err)
	}
	t.Logf("latency probe says node is HEALTHY: %dms", delay)

	// The throughput probe is not fooled.
	result, _ := URLTestThroughput(ctx, server.URL, DefaultThroughputBytes, directDialer{})
	t.Logf("throughput probe carried %d bytes (needed %d)", result.CarriedBytes, DefaultMinCarriedBytes)

	if result.CarriedBytes >= DefaultMinCarriedBytes {
		t.Fatalf("frozen node must fail the evidence bar, but carried %d bytes", result.CarriedBytes)
	}
	if result.CarriedBytes > freezeAt {
		t.Fatalf("carried more than the server ever sent: %d", result.CarriedBytes)
	}
}

// A healthy server must pass and report a plausible rate, or the filter would
// evict everything.
func TestHealthyServerPassesProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(make([]byte, DefaultThroughputBytes))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := URLTestThroughput(ctx, server.URL, DefaultThroughputBytes, directDialer{})
	if err != nil {
		t.Fatalf("healthy server probe failed: %v", err)
	}
	if result.CarriedBytes < DefaultMinCarriedBytes {
		t.Fatalf("healthy server carried only %d bytes", result.CarriedBytes)
	}
	t.Logf("healthy node carried %d bytes at %d KB/s", result.CarriedBytes, result.KBps)
}

// A server that accepts the connection and then never responds at all must not
// hang the prober past its deadline.
func TestBlackholeServerTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and say nothing, ever.
			_ = conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	result, err := URLTestThroughput(ctx, "http://"+ln.Addr().String()+"/x", DefaultThroughputBytes, directDialer{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("blackhole server should produce an error")
	}
	if result.CarriedBytes != 0 {
		t.Fatalf("blackhole carried %d bytes", result.CarriedBytes)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("probe did not respect deadline, took %v", elapsed)
	}
	t.Logf("blackhole correctly failed after %v: %v", elapsed.Round(time.Millisecond), err)
}
