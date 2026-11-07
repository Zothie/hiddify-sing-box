package hydra

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Parameterised WS-upgrade fragmentation (NoDPI-style, mirrors the Rust
// client's frag.rs): the first TCP segment of the first flight carries a small
// cut (at or inside the SNI for a ClientHello, or the head of the WS-upgrade
// request), the rest are sent in bounded pieces. The conn-level splitter
// splits whatever the TLS layer emits in one Write, so a record written as a
// single Write arrives as several wire segments.
const (
	splitFirstMin = 8
	splitFirstMax = 64
	splitRestMin  = 16
	splitRestMax  = 96

	// splitDelayDefaultMs is the Rust client's SPLIT_DELAY (frag.rs:35) and
	// the zero-resolution of SplitParams.SplitDelayMs.
	splitDelayDefaultMs = 1

	// maxAttackBudgetPieces bounds the first-flight piece count under the
	// reference server's upgrade attack check (tungstenite AttackCheck,
	// measured live: >64 reads averaging <128B are reset). The margin keeps
	// realistic flights (6-10 pieces) far below the limit even with an
	// adversarial rest_min from a signed catalogue.
	maxAttackBudgetPieces = 56
)

// Validation clamps for the catalogue axes (TUNING.md A1-A4).
const (
	splitFirstClampMin = 1
	splitFirstClampMax = 64
	splitRestClampMin  = 1
	splitRestClampMax  = 96
	splitDelayClampMs  = 50
	disorderClampMs    = 100
	disorderDefaultMs  = 10
	// disorderFallbackTTL is the restore value when getsockopt cannot read
	// the socket's saved TTL (Rust client: ttl().unwrap_or(64)).
	disorderFallbackTTL = 64
)

// SplitParams carries the fragmentation/disorder axes of a candidate.
// The zero value is the Rust client's frag.rs baseline (TUNING.md
// 01-hydra-wss-frag): first segment uniform in [8,64], rest pieces uniform in
// [16,96], 1ms inter-segment sleep, disorder off. Caller-supplied ranges
// override each axis; values are clamped, never rejected, so a bad catalogue
// entry degrades to the nearest legal axis instead of breaking the candidate.
type SplitParams struct {
	// FirstMin/FirstMax bound the size of the FIRST segment, clamped to
	// [1,64] (A1 frag_first_min/max). min==max fixes the size; min<max picks
	// a fresh uniform value per connection.
	FirstMin int
	FirstMax int
	// RestMin/RestMax bound every following piece of the first flight,
	// clamped to [1,96] (A2 frag_rest_min/max; Rust default 16..96).
	// min==max fixes the piece size; min<max randomises per piece.
	RestMin int
	RestMax int
	// SplitDelayMs sleeps between the segments of the first flight, clamped
	// to [0,50] (A3 split_delay_ms). 0 selects the Rust default (1ms).
	SplitDelayMs int
	// Disorder sends the first flight with IP TTL=1 on the BASE TCP socket
	// below TLS so it dies at the first router hop, then restores the saved
	// TTL; TCP retransmits the lost segment with the normal TTL (A4
	// HYDRA_DISORDER). Applied by ttlDisorderDialer, not by helloSplitConn.
	Disorder bool
	// DisorderDelayMs is the pacing sleep after the TTL restore, clamped to
	// [1,100]; 0 selects the default (10ms, the Rust client's value).
	DisorderDelayMs int
	// Logger receives fallback reasons; nil is allowed and silences logging.
	Logger log.ContextLogger
}

func (p SplitParams) normalized() SplitParams {
	q := p
	if q.FirstMin <= 0 && q.FirstMax <= 0 {
		q.FirstMin, q.FirstMax = splitFirstMin, splitFirstMax
	}
	q.FirstMin = clampInt(q.FirstMin, splitFirstClampMin, splitFirstClampMax)
	q.FirstMax = clampInt(q.FirstMax, splitFirstClampMin, splitFirstClampMax)
	if q.FirstMin > q.FirstMax {
		q.FirstMin, q.FirstMax = q.FirstMax, q.FirstMin
	}
	if q.RestMin <= 0 && q.RestMax <= 0 {
		q.RestMin, q.RestMax = splitRestMin, splitRestMax
	}
	q.RestMin = clampInt(q.RestMin, splitRestClampMin, splitRestClampMax)
	q.RestMax = clampInt(q.RestMax, splitRestClampMin, splitRestClampMax)
	if q.RestMin > q.RestMax {
		q.RestMin, q.RestMax = q.RestMax, q.RestMin
	}
	if q.SplitDelayMs <= 0 {
		q.SplitDelayMs = splitDelayDefaultMs
	}
	q.SplitDelayMs = clampInt(q.SplitDelayMs, 0, splitDelayClampMs)
	if q.DisorderDelayMs <= 0 {
		q.DisorderDelayMs = disorderDefaultMs
	}
	q.DisorderDelayMs = clampInt(q.DisorderDelayMs, 1, disorderClampMs)
	return q
}

func (p SplitParams) logWarn(args ...any) {
	if p.Logger != nil {
		p.Logger.Warn(args...)
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// randBetween returns a uniform value in [lo,hi]; equal bounds are fixed.
func randBetween(lo, hi int) int {
	if lo >= hi {
		return lo
	}
	return lo + rand.Intn(hi-lo+1)
}

// helloSplitConn fragments the FIRST Write on the underlying TLS connection.
// Later writes pass through untouched.
type helloSplitConn struct {
	net.Conn
	mu       sync.Mutex
	first    bool
	params   SplitParams // normalized
	segments int         // wire segments of the first flight so far
}

func newHelloSplitConn(c net.Conn) *helloSplitConn {
	return newHelloSplitConnParams(c, SplitParams{})
}

func newHelloSplitConnParams(c net.Conn, params SplitParams) *helloSplitConn {
	return &helloSplitConn{Conn: c, first: true, params: params.normalized()}
}

// SegmentsWritten reports how many wire segments the first flight was sent in.
func (c *helloSplitConn) SegmentsWritten() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.segments
}

func (c *helloSplitConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	isFirst := c.first
	if isFirst {
		c.first = false
	}
	c.mu.Unlock()
	if !isFirst {
		return c.Conn.Write(b)
	}
	first := randBetween(c.params.FirstMin, c.params.FirstMax)
	if first > len(b) || len(b) <= c.params.FirstMax {
		// Rust frag.rs:43-45: a record no larger than the first-segment
		// ceiling (a <=64B ClientHello) is never split.
		first = len(b)
	}
	restMin, restMax := c.params.RestMin, c.params.RestMax
	// Server-side attack budget: the reference server's upgrade handler
	// (tungstenite AttackCheck, measured live) resets connections whose
	// first flight arrives in >64 reads averaging <128B. An adversarial
	// rest_min with a long record could trip it — raise the rest floor so
	// the projected piece count stays under the budget.
	if budget := maxAttackBudgetPieces; len(b) > first && (len(b)-first+restMin-1)/restMin > budget {
		restMin = (len(b) - first + budget - 1) / budget
		if restMax < restMin {
			restMax = restMin
		}
	}
	delay := time.Duration(c.params.SplitDelayMs) * time.Millisecond
	written := 0
	for written < len(b) {
		take := len(b) - written
		if written == 0 {
			take = min(take, first)
		} else {
			take = min(take, randBetween(restMin, restMax))
		}
		if _, err := c.Conn.Write(b[written : written+take]); err != nil {
			return written, err
		}
		written += take
		c.mu.Lock()
		c.segments++
		c.mu.Unlock()
		if written < len(b) && delay > 0 {
			time.Sleep(delay)
		}
	}
	return len(b), nil
}

// splitDialer wraps a TLS dialer so every produced connection fragments its
// first record per Params (zero value = the Rust client's frag.rs baseline).
type splitDialer struct {
	N.Dialer
	Params SplitParams
}

func (d splitDialer) DialContext(ctx context.Context, network string,
	destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		// Fragmentation is a TCP trick; never chop datagram writes.
		return d.Dialer.DialContext(ctx, network, destination)
	}
	c, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return newHelloSplitConnParams(c, d.Params), nil
}

// ttlDisorderDialer wraps the BASE dialer (the plain TCP dialer below TLS,
// NOT the TLS dialer): the produced socket's first flight goes out with IP
// TTL=1 and dies at the first router hop; the saved TTL is restored right
// after the first Write, and TCP retransmits the lost segment with the normal
// TTL while the rest of the flight proceeds. Every disorder failure falls
// back to plain fragmentation with a logged reason - never a failed dial.
type ttlDisorderDialer struct {
	N.Dialer
	Params SplitParams
}

func (d ttlDisorderDialer) DialContext(ctx context.Context, network string,
	destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		// TTL=1 is a TCP trick; never arm it on a datagram socket.
		return d.Dialer.DialContext(ctx, network, destination)
	}
	c, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	params := d.Params.normalized()
	if !params.Disorder {
		return c, nil
	}
	if dc, applied := newTTLDisorderConn(c, params); applied {
		return dc, nil
	}
	return c, nil
}

// ttlDisorderConn is the socket-level arm of the disorder trick. The TLS
// layer's first Write passes through with TTL=1; on its success the saved TTL
// is restored and the pacing delay is slept inline, so every later Write
// (including TCP's retransmission of the lost segment) uses the normal TTL.
type ttlDisorderConn struct {
	net.Conn
	mu       sync.Mutex
	savedTTL int           // getsockopt before the change; 64 when unreadable
	setTo    int           // 1 while TTL=1 is armed; 0 when inert
	delay    time.Duration // pacing sleep after the restore
	restored bool
}

// newTTLDisorderConn arms TTL=1 on a fresh TCP socket. It returns applied
// false (with the conn untouched) for non-TCP conns or any socket-option
// failure, so the caller falls back to plain fragmentation.
func newTTLDisorderConn(raw net.Conn, params SplitParams) (*ttlDisorderConn, bool) {
	tcp, isTCP := raw.(*net.TCPConn)
	if !isTCP {
		params.logWarn("hydra: disorder skipped: conn is not a TCP conn")
		return nil, false
	}
	v6 := false
	if ra, ok := tcp.RemoteAddr().(*net.TCPAddr); ok && ra.IP != nil {
		v6 = ra.IP.To4() == nil
	}
	dc := &ttlDisorderConn{
		Conn:     raw,
		savedTTL: disorderFallbackTTL,
		setTo:    1,
		delay:    time.Duration(params.DisorderDelayMs) * time.Millisecond,
	}
	var setErr, ctlErr error
	rc, err := tcp.SyscallConn()
	if err == nil {
		err = rc.Control(func(fd uintptr) {
			if saved, readErr := sockReadTTL(fd, v6); readErr == nil {
				dc.savedTTL = saved
			} else {
				params.logWarn("hydra: disorder: cannot read saved TTL (fallback 64): ", readErr)
			}
			setErr = sockWriteTTL(fd, v6, 1)
		})
	}
	if err != nil {
		ctlErr = err
	}
	if ctlErr != nil || setErr != nil {
		params.logWarn("hydra: disorder fallback (TTL=1 not set): ctl=",
			ctlErr, " set=", setErr)
		return nil, false
	}
	return dc, true
}

// Applied reports whether TTL=1 was actually armed on the socket.
func (c *ttlDisorderConn) Applied() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setTo == 1
}

// SavedTTL returns the TTL read from the socket before the change.
func (c *ttlDisorderConn) SavedTTL() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.savedTTL
}

// Restore puts the socket back onto its saved TTL and returns that value.
// Idempotent.
func (c *ttlDisorderConn) Restore() int {
	c.mu.Lock()
	saved := c.savedTTL
	armed := c.setTo == 1 && !c.restored
	if armed {
		c.restored = true
	}
	c.mu.Unlock()
	if armed {
		if tcp, ok := c.Conn.(*net.TCPConn); ok {
			v6 := false
			if ra, ok := tcp.RemoteAddr().(*net.TCPAddr); ok && ra.IP != nil {
				v6 = ra.IP.To4() == nil
			}
			if raw, err := tcp.SyscallConn(); err == nil {
				_ = raw.Control(func(fd uintptr) {
					_ = sockWriteTTL(fd, v6, saved)
				})
			}
		}
	}
	return saved
}

// Restored reports whether the saved TTL has been put back.
func (c *ttlDisorderConn) Restored() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restored
}

func (c *ttlDisorderConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil && c.Applied() && !c.Restored() {
		c.Restore()
		if c.delay > 0 {
			time.Sleep(c.delay)
		}
	}
	return n, err
}

func (c *ttlDisorderConn) Close() error {
	c.Restore() // never close a socket left on TTL=1
	return c.Conn.Close()
}
