package hydra

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestOpenCancellationWithFullQueue(t *testing.T) {
	tunnel := &Tunnel{out: make(chan []byte, 1), done: make(chan struct{}), sessions: make(map[[IDSize]byte]*session)}
	tunnel.out <- []byte("occupied")
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan error, 1)
	go func() {
		_, err := tunnel.openSession(ctx, "127.0.0.1", 443)
		finished <- err
	}()
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled open succeeded")
		}
	case <-time.After(time.Second):
		close(tunnel.done)
		<-finished
		t.Fatal("session open ignored cancellation behind full queue")
	}
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	if len(tunnel.sessions) != 0 {
		t.Fatal("canceled session leaked")
	}
}

func TestSessionCleanupWithFullQueue(t *testing.T) {
	for _, udp := range []bool{false, true} {
		tunnel := &Tunnel{out: make(chan []byte, 1), done: make(chan struct{}), sessions: make(map[[IDSize]byte]*session), udp: make(map[[IDSize]byte]*udpSession)}
		tunnel.out <- []byte("occupied")
		finished := make(chan struct{})
		go func() {
			if udp {
				_ = tunnel.openUDP().Close()
			} else {
				_ = newSession(tunnel, [IDSize]byte{}).Close()
			}
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(time.Second):
			close(tunnel.done)
			<-finished
			t.Fatal("session cleanup blocked behind full queue")
		}
		select {
		case <-tunnel.done:
			t.Fatal("cleanup killed the shared tunnel")
		default:
		}
	}
}

func TestHandshakeCancellationClosesRawConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	dialed := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		_, err := connectTunnel(ctx, func(context.Context) (net.Conn, error) {
			close(dialed)
			return client, nil
		}, &url.URL{Scheme: "ws", Host: "127.0.0.1", Path: "/"}, http.Header{}, make([]byte, 32), nil)
		finished <- err
	}()
	<-dialed
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake ignored cancellation while writing HTTP upgrade")
	}
}
