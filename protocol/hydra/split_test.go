package hydra

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// fakeConn records every Write as a separate segment.
type fakeConn struct {
	segments [][]byte
	closed   bool
}

func (c *fakeConn) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	c.segments = append(c.segments, cp)
	return len(b), nil
}

func (c *fakeConn) Read(b []byte) (int, error)          { return 0, errors.New("read") }
func (c *fakeConn) Close() error                        { c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr                 { return nil }
func (c *fakeConn) RemoteAddr() net.Addr                { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error       { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error  { return nil }

func TestHelloSplitFirstRecord(t *testing.T) {
	fc := &fakeConn{}
	c := newHelloSplitConn(fc)
	payload := make([]byte, 517) // typical ClientHello record size
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if len(fc.segments) < 2 {
		t.Fatalf("expected >=2 segments, got %d", len(fc.segments))
	}
	first := len(fc.segments[0])
	if first < splitFirstMin || first > splitFirstMax {
		t.Fatalf("first segment %d outside [%d,%d]", first, splitFirstMin, splitFirstMax)
	}
	for i, seg := range fc.segments[1:] {
		if len(seg) > splitRestMax {
			t.Fatalf("segment %d len %d > %d", i, len(seg), splitRestMax)
		}
	}
	var got bytes.Buffer
	for _, seg := range fc.segments {
		got.Write(seg)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatal("payload corrupted by splitting")
	}
}

func TestHelloSplitSubsequentWritesPassThrough(t *testing.T) {
	fc := &fakeConn{}
	c := newHelloSplitConn(fc)
	c.Write(make([]byte, 300))
	n := len(fc.segments)
	c.Write(make([]byte, 400))
	if len(fc.segments) != n+1 {
		t.Fatalf("second write must NOT be split: %d -> %d segments", n, len(fc.segments))
	}
}
