// Package controlclient manages the app-owned Tor control daemon
// (tor-control-daemon, built from the hydra source tree) and fetches the
// signed capability catalogue through its loopback SOCKS5 listener.
//
// Purpose boundary: user data NEVER goes through Tor. The only payload is the
// signed capability catalogue, fetched as plain HTTP over the onion circuit
// (the daemon adds no TLS; Tor encrypts). Signature verification is the
// caller's job (protocol/hydra catalogue verifier); this package returns the
// raw bytes.
//
// Fail-closed contract: if the daemon is not running or its SOCKS listener is
// dead, FetchCatalogue returns an error. There is NO direct-network fallback
// in this package.
//
// Bootstrap progress: the daemon prints parsable "BOOTSTRAP ..." lines on
// stderr; this package parses them into BootstrapState callbacks.
package controlclient

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Bounded restart policy for an unexpectedly dead daemon.
	maxRestarts       = 5
	restartBackoff0   = 250 * time.Millisecond
	restartBackoffMax = 2 * time.Second

	defaultControlPort = 80
	bootstrapChanCap   = 32
	maxControlBody     = 256 * 1024
)

// Config for Start.
type Config struct {
	// DaemonPath is the tor-control-daemon binary. We own the process.
	DaemonPath string
	// SocksAddr must be a loopback address (127.0.0.1, ::1 or "localhost").
	// Port 0 is allowed: the daemon binds an ephemeral port and announces the
	// real one in its BOOTSTRAP ready line.
	SocksAddr string
	// DataDir for the daemon's Arti state/cache (real mode).
	DataDir string
	// ControlOnion is the onion address of the control service, e.g.
	// "xyz.onion" or "xyz.onion:80".
	ControlOnion string
	// ExtraArgs are appended verbatim to the daemon command line. This is the
	// support seam for mock/test modes (--mock-file, --mock-tor,
	// --hook-fail-test) and must stay empty in production.
	ExtraArgs []string
}

// BootstrapState is one parsed daemon stderr line.
type BootstrapState struct {
	Ready bool
	Text  string
}

// Client owns the daemon process.
type Client struct {
	cfg Config

	// target host/port parsed from ControlOnion.
	onionHost string
	onionPort int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	states chan BootstrapState

	mu      sync.Mutex
	cmd     *exec.Cmd
	ready   bool
	gen     int    // incremented on every daemon spawn (restart detection)
	annAddr string // socks addr announced by the daemon (for port 0 configs)

	// alive mirrors cmd.ProcessState without racing cmd.Wait: the supervisor
	// clears it after Wait returns, fetches check it instead of touching
	// ProcessState directly.
	alive   atomic.Bool
	stopped bool
	stopErr error
}

// Start validates the config, spawns the daemon and starts the restart
// supervisor. The daemon is killed when ctx is done or Close is called.
func Start(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.DaemonPath == "" {
		return nil, errors.New("controlclient: DaemonPath is empty")
	}
	if err := requireLoopback(cfg.SocksAddr); err != nil {
		return nil, err
	}
	host, port, err := splitOnion(cfg.ControlOnion)
	if err != nil {
		return nil, err
	}

	c := &Client{
		cfg:       cfg,
		onionHost: host,
		onionPort: port,
		states:    make(chan BootstrapState, bootstrapChanCap),
	}
	c.ctx, c.cancel = context.WithCancel(context.WithoutCancel(ctx))

	if err := c.spawn(); err != nil {
		c.cancel()
		return nil, err
	}

	c.wg.Add(1)
	go c.supervise()

	// Kill the daemon when the caller's ctx is done.
	if ctx != nil {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			select {
			case <-ctx.Done():
				c.cancel()
			case <-c.ctx.Done():
			}
		}()
	}
	return c, nil
}

// BootstrapStates streams parsed daemon BOOTSTRAP lines.
func (c *Client) BootstrapStates() <-chan BootstrapState { return c.states }

// Ready reports whether the daemon announced its SOCKS listener.
func (c *Client) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ready
}

// generation counts daemon spawns (initial + restarts); used to observe a
// restart actually happening instead of racing on the ready flag.
func (c *Client) generation() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// FetchCatalogue fetches GET /catalogue over the daemon's SOCKS5 listener on
// the control onion circuit and returns the raw response body bytes. It never
// falls back to a direct connection.
func (c *Client) FetchCatalogue(ctx context.Context) ([]byte, error) {
	return c.FetchPath(ctx, "/catalogue")
}

// FetchPath fetches the catalogue or its detached signature through Tor only.
func (c *Client) FetchPath(ctx context.Context, path string) ([]byte, error) {
	if path != "/catalogue" && path != "/catalogue.sig" {
		return nil, errors.New("controlclient: unsupported control path")
	}
	c.mu.Lock()
	cmd := c.cmd
	alive := cmd != nil && c.alive.Load()
	socks := c.cfg.SocksAddr
	if c.cfg.port() == 0 && c.annAddr != "" {
		socks = c.annAddr
	}
	c.mu.Unlock()
	if !alive {
		return nil, errors.New("controlclient: daemon not running; refusing clearnet fallback")
	}

	conn, err := socksDial(ctx, socks, c.onionHost, c.onionPort)
	if err != nil {
		return nil, fmt.Errorf("controlclient: socks dial: %w", err)
	}
	defer conn.Close()
	return httpGetPath(ctx, conn, c.onionHost, path)
}

// Close kills the daemon and waits for the supervisor to stop.
func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	cmd := c.cmd
	c.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	c.wg.Wait()
	return nil
}

func (cfg Config) port() int {
	_, p, err := net.SplitHostPort(cfg.SocksAddr)
	if err != nil {
		return -1
	}
	var v int
	fmt.Sscanf(p, "%d", &v)
	return v
}

func (c *Client) daemonArgs() []string {
	args := []string{
		"--socks-listen", c.cfg.SocksAddr,
		"--data-dir", c.cfg.DataDir,
		"--control-onion", c.cfg.ControlOnion,
	}
	return append(args, c.cfg.ExtraArgs...)
}

func (c *Client) spawn() error {
	cmd := exec.Command(c.cfg.DaemonPath, c.daemonArgs()...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("controlclient: stderr pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("controlclient: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("controlclient: start daemon: %w", err)
	}
	c.mu.Lock()
	c.cmd = cmd
	c.ready = false
	c.gen++
	c.mu.Unlock()
	c.alive.Store(true)

	c.wg.Add(2)
	go c.readStderr(stderr)
	go c.drainStdout(stdout)
	return nil
}

// supervise restarts the daemon with bounded backoff after unexpected death;
// it stops when the client context is cancelled (caller ctx done or Close).
func (c *Client) supervise() {
	defer c.wg.Done()
	attempts := 0
	for {
		c.mu.Lock()
		cmd := c.cmd
		c.mu.Unlock()
		waitErr := cmd.Wait()
		c.alive.Store(false)

		select {
		case <-c.ctx.Done():
			c.mu.Lock()
			c.stopped = true
			c.mu.Unlock()
			return
		default:
		}

		if attempts >= maxRestarts {
			c.fail(fmt.Errorf("controlclient: daemon exited %d times (last: %v)", attempts+1, waitErr))
			return
		}
		backoff := restartBackoff0 << attempts
		if backoff > restartBackoffMax {
			backoff = restartBackoffMax
		}
		select {
		case <-time.After(backoff):
		case <-c.ctx.Done():
			c.mu.Lock()
			c.stopped = true
			c.mu.Unlock()
			return
		}
		attempts++
		if err := c.spawn(); err != nil {
			c.fail(err)
			return
		}
	}
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	c.stopped = true
	if c.stopErr == nil {
		c.stopErr = err
	}
	c.mu.Unlock()
}

func (c *Client) readStderr(r io.Reader) {
	defer c.wg.Done()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "BOOTSTRAP ") {
			continue
		}
		ready, _ := extractField(line, "ready=")
		addr, announced := extractField(line, "socks=")
		listenerReady := false
		if ready == "true" && announced && requireLoopback(addr) == nil {
			_, port, err := net.SplitHostPort(addr)
			_, portErr := parsePort(port)
			listenerReady = err == nil && portErr == nil
		}
		st := BootstrapState{Ready: listenerReady, Text: line}
		c.mu.Lock()
		c.ready = st.Ready
		if listenerReady {
			c.annAddr = addr
		}
		c.mu.Unlock()
		select {
		case c.states <- st:
		default: // drop if the consumer is not keeping up
		}
	}
}

func extractField(line, key string) (string, bool) {
	idx := strings.Index(line, key)
	if idx < 0 {
		return "", false
	}
	rest := line[idx+len(key):]
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		return rest, true
	}
	return rest[:end], true
}

func (c *Client) drainStdout(r io.Reader) {
	defer c.wg.Done()
	// The daemon contract is zero stdout noise; drain defensively.
	_, _ = io.Copy(io.Discard, r)
}

// requireLoopback refuses non-loopback SOCKS addresses (the listener is an
// app-internal seam and must never be exposed).
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("controlclient: bad SocksAddr %q: %w", addr, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("controlclient: refusing non-loopback SocksAddr %q", addr)
	}
	return nil
}

func splitOnion(onion string) (string, int, error) {
	host := onion
	port := defaultControlPort
	if h, p, err := net.SplitHostPort(onion); err == nil {
		host = h
		pp, err := parsePort(p)
		if err != nil {
			return "", 0, fmt.Errorf("controlclient: bad ControlOnion %q: %w", onion, err)
		}
		port = pp
	}
	if !strings.HasSuffix(strings.ToLower(host), ".onion") {
		return "", 0, fmt.Errorf("controlclient: ControlOnion %q is not an .onion address", onion)
	}
	return strings.ToLower(host), port, nil
}

func parsePort(s string) (int, error) {
	var p int
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return p, nil
}

// socksDial performs an RFC1928 CONNECT (no auth) handshake over the daemon's
// loopback SOCKS5 listener and returns the established stream. Onion names
// are passed as ATYP=domain; the daemon routes .onion over Tor (no DNS).
func socksDial(ctx context.Context, socksAddr, host string, port int) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		// No caller deadline: still bound the control-plane handshake and the
		// catalogue exchange so a hung daemon cannot park this call forever.
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("greeting write: %w", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		conn.Close()
		return nil, fmt.Errorf("greeting read: %w", err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks greeting rejected (ver=0x%02x method=0x%02x)", greet[0], greet[1])
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var portBE [2]byte
	binary.BigEndian.PutUint16(portBE[:], uint16(port))
	req = append(req, portBE[:]...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connect write: %w", err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connect reply read: %w", err)
	}
	if hdr[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("bad socks reply version 0x%02x", hdr[0])
	}
	if hdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks CONNECT refused, rep=0x%02x", hdr[1])
	}
	var extra int
	switch hdr[3] {
	case 0x01:
		extra = 4 + 2
	case 0x04:
		extra = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, fmt.Errorf("reply atyp read: %w", err)
		}
		extra = int(l[0]) + 2
	default:
		conn.Close()
		return nil, fmt.Errorf("bad socks reply atyp 0x%02x", hdr[3])
	}
	rest := make([]byte, extra)
	if _, err := io.ReadFull(conn, rest); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reply tail read: %w", err)
	}
	return conn, nil
}

// httpGetCatalogue speaks plain HTTP/1.0 over the established SOCKS stream.
func httpGetCatalogue(ctx context.Context, conn net.Conn, host string) ([]byte, error) {
	return httpGetPath(ctx, conn, host, "/catalogue")
}

// httpGetPath speaks plain HTTP/1.0 for one path over the SOCKS stream.
func httpGetPath(ctx context.Context, conn net.Conn, host, path string) ([]byte, error) {
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("catalogue request write: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("catalogue response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalogue fetch: unexpected status %d", resp.StatusCode)
	}
	limit := maxControlBody
	if path == "/catalogue.sig" {
		limit = 1024
	}
	if resp.ContentLength > int64(limit) {
		return nil, errors.New("controlclient: response exceeds size limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("catalogue body: %w", err)
	}
	if len(body) > limit {
		return nil, errors.New("controlclient: response exceeds size limit")
	}
	return body, nil
}
