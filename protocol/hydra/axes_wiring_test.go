package hydra

// Wire-level proof that the candidate axis fields put on the wire by the
// outbound dialer chain are exactly the ones the option layer carries
// (option -> splitParamsFromOption -> SplitParams -> splitDialer/ttlDisorderDialer),
// using the exported introspection seams (per-Write recording + the
// SegmentsWritten/Applied/Restored/SavedTTL accessors) on REAL loopback TCP
// sockets (setsockopt works on loopback; the death branch itself is proven
// in the netns lab — split_test.go).

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// recordingConn sits UNDER helloSplitConn and records the length of every
// Write — each Write is one wire segment of the first flight.
type recordingConn struct {
	net.Conn
	sizes []int
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.sizes = append(c.sizes, len(b))
	return c.Conn.Write(b)
}

func localListener(t *testing.T) (addr string, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c) // drain; never reply
		}
	}()
	return l.Addr().String(), func() { _ = l.Close() }
}

func TestAxesSplitParamsReachTheWire(t *testing.T) {
	addr, stop := localListener(t)
	defer stop()

	// Option-level values, mapped exactly the way the outbound maps them.
	params := splitParamsFromOption(20, 30, 40, 80, 0, 0, false, nil)
	base, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingConn{Conn: base}
	conn := newHelloSplitConnParams(rec, params)
	payload := make([]byte, 1024)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if got := conn.SegmentsWritten(); got != len(rec.sizes) || got < 10 {
		t.Fatalf("segments = %d (sizes=%d), want >= 10 matching recordings", got, len(rec.sizes))
	}
	if first := rec.sizes[0]; first < 20 || first > 30 {
		t.Fatalf("first segment = %d, want within the option range 20..30", first)
	}
	for i, size := range rec.sizes[1:] {
		last := i+1 == len(rec.sizes)-1
		// The final piece is the remainder of the record: it can be any
		// size below the range ceiling. Only full rest pieces are bounded
		// by the option range from below.
		if last && size > 80 {
			t.Fatalf("final segment = %d, want <= 80", size)
		}
		if !last && (size < 40 || size > 80) {
			t.Fatalf("segment %d = %d, want within the option rest range 40..80", i+1, size)
		}
	}
	_ = base.Close()
}

func TestAxesSplitDelayKnobReachesTheWire(t *testing.T) {
	addr, stop := localListener(t)
	defer stop()

	// split_delay_ms=20 through the option mapping paces the first flight.
	params := splitParamsFromOption(0, 0, 80, 96, 20, 0, false, nil)
	base, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	conn := newHelloSplitConnParams(base, params)
	start := time.Now()
	if _, err := conn.Write(make([]byte, 300)); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	segments := conn.SegmentsWritten()
	// 300B at 80..96 pieces -> >= 4 segments -> >= 3 sleeps of 20ms.
	if segments < 4 || elapsed < time.Duration(segments-1)*15*time.Millisecond {
		t.Fatalf("delay knob dead: %d segments in %s", segments, elapsed)
	}
}

func TestAxesDisorderDialerArmsOnRealTCP(t *testing.T) {
	addr, stop := localListener(t)
	defer stop()

	// The disorder axis wraps the BASE dialer and arms TTL=1 on a real
	// socket; the saved TTL is restored after the first write (loopback
	// delivers regardless — the death branch is the netns lab's proof).
	params := splitParamsFromOption(0, 0, 0, 0, 0, 0, true, nil)
	base, derr := dialer.New(context.Background(), option.DialerOptions{}, false)
	if derr != nil {
		t.Fatal(derr)
	}
	dialer := ttlDisorderDialer{Dialer: base, Params: params}
	conn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(addr))
	if err != nil {
		t.Fatal(err)
	}
	dc, ok := conn.(*ttlDisorderConn)
	if !ok {
		t.Fatalf("disorder dialer produced %T, want *ttlDisorderConn", conn)
	}
	if !dc.Applied() {
		t.Fatal("TTL=1 not armed on a real TCP socket")
	}
	if dc.SavedTTL() < 1 {
		t.Fatalf("saved TTL = %d, want a real socket value >= 1", dc.SavedTTL())
	}
	if _, err := dc.Write(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if !dc.Restored() {
		t.Fatal("saved TTL not restored after the first write")
	}
	if _, err := dc.Write(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	_ = dc.Close()
}
