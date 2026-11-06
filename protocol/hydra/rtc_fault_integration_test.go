package hydra

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestRTCRealServerShortShard checks authentic server bodies before frame decode.
// The UDP relay drops one short shard, retaining its authenticated original for
// comparison. No ciphertext or parity is synthesized by this test.
func TestRTCRealServerShortShard(t *testing.T) {
	_, addr, pub, _ := startRustServerRTC(t, writeSharedKey(t))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		for i := 0; i < 48; i++ {
			// Separate TCP reads produce full and short reliable shards together.
			if _, e = c.Write(bytes.Repeat([]byte{byte(i + 1)}, 8192)); e != nil {
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()
	upstream, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, e := relay.ReadFrom(buf)
			if e != nil {
				return
			}
			if _, e = upstream.Write(buf[:n]); e != nil {
				return
			}
		}
	}()
	packets := make(chan []byte, 256)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, e := upstream.Read(buf)
			if e != nil {
				return
			}
			select {
			case packets <- append([]byte(nil), buf[:n]...):
			case <-t.Context().Done():
				return
			}
		}
	}()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	peer := relay.LocalAddr().(*net.UDPAddr)
	engine := NewClient(pub, peer.AddrPort(), time.Now())
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	opened := false
	var original []byte
	var lost, base uint32
	full := make(map[uint32]bool)
	paritySeen := false
	started := time.Now()
	for {
		select {
		case <-deadline.C:
			t.Fatalf("no completed repair: lost=%d parity=%v", lost, paritySeen)
		case <-tick.C:
			poll := engine.Poll(time.Now())
			for _, p := range poll.Wire {
				if _, e := pc.WriteTo(p, peer); e != nil {
					t.Fatal(e)
				}
			}
			if engine.Connected() && !opened {
				opened = true
				a := listener.Addr().(*net.TCPAddr)
				frame := append([]byte{0}, make([]byte, IDSize)...)
				frame = append(frame, 9)
				frame = append(frame, "127.0.0.1"...)
				frame = binary.BigEndian.AppendUint16(frame, uint16(a.Port))
				engine.SendFrame(frame)
			}
		case p := <-packets:
			var retransmitted []byte
			if engine.rtcCipher != nil && len(p) >= RTPHeaderLen+NonceSize+16 && p[0]&0xc0 == 0x80 && p[1]&0x7f == RTPPtOpus {
				ctr, body, ok := openMask(engine.rtcCipher, p[RTPHeaderLen:])
				if ok && ctr >= dataCounterBase && ctr < parityCounterBase && len(body) >= 4 {
					seq := uint32FromBE(body[:4])
					group := ((seq-1)/FecGroup)*FecGroup + 1
					if len(body) == Chunk+4 {
						full[group] = true
					}
					if lost == 0 && full[group] && len(body) > 4 && len(body) < Chunk+4 {
						lost, base, original = seq, group, append([]byte(nil), body[4:]...)
						t.Logf("relay dropped authentic short seq=%d group=%d original=%d", lost, base, len(original))
						continue
					}
					// Only drop the first transmission; retransmission must repair it.
					if seq == lost && original != nil {
						retransmitted = append([]byte(nil), body[4:]...)
						t.Logf("authentic retransmission seq=%d length=%d after=%s", seq, len(body)-4, time.Since(started))
					}
				}
			}
			engine.Receive(p, time.Now())
			if retransmitted != nil && engine.input.expected > lost {
				{
					recovered := retransmitted
					first := 0
					for first < len(original) && first < len(recovered) && original[first] == recovered[first] {
						first++
					}
					detail := fmt.Sprintf("seq=%d original=%d reconstructed=%d first_difference=%d elapsed=%s", lost, len(original), len(recovered), first, time.Since(started))
					if !bytes.Equal(original, recovered) {
						t.Fatal(detail)
					}
					t.Log(detail)
					return
				}
			}
		}
	}
}

// Exercise actual encrypted datagrams between the Go transport and Rust server.
// Delay one short server data packet until parity has crossed the relay.
func TestRTCRealServerPacketReorder(t *testing.T) {
	_, addr, pub, _ := startRustServerRTC(t, writeSharedKey(t))
	upstream, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	client := make(chan net.Addr, 1)
	go func() {
		buf := make([]byte, 65536)
		first := true
		for {
			n, a, e := relay.ReadFrom(buf)
			if e != nil {
				return
			}
			if first {
				client <- a
				first = false
			}
			if _, e = upstream.Write(buf[:n]); e != nil {
				return
			}
		}
	}()
	delayed := make(chan int, 1)
	go func() {
		a := <-client
		buf := make([]byte, 65536)
		var held []byte
		largeCount := 0
		didHold := false
		for {
			n, e := upstream.Read(buf)
			if e != nil {
				return
			}
			// RTP data: exclude CONFIRM and small control frames by waiting for a
			// full-sized packet, then hold the next shorter data packet.
			if n > 1000 && buf[0]&0xc0 == 0x80 && buf[1]&0x7f == RTPPtOpus {
				largeCount++
				didHold = largeCount > 10
			}
			if didHold && held == nil && n > 100 && n < 1000 && buf[0]&0xc0 == 0x80 && buf[1]&0x7f == RTPPtOpus {
				held = append([]byte(nil), buf[:n]...)
				delayed <- n
				// Genuine network reordering: original ciphertext arrives unchanged.
				packet := held
				go func() { time.Sleep(900 * time.Millisecond); relay.WriteTo(packet, a) }()
				continue
			}
			if _, e = relay.WriteTo(buf[:n], a); e != nil {
				return
			}
		}
	}()
	ap := relay.LocalAddr().(*net.UDPAddr).AddrPort()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	tun, err := connectTunnelRTC(ctx, func(ctx context.Context) (net.PacketConn, error) {
		var lc net.ListenConfig
		return lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
	}, pub[:], netip.AddrPortFrom(ap.Addr(), ap.Port()), nil, 16384)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	origin, roots := startProofOrigin(t, 128*1024)
	err = verifyTunnelProof(ctx, tun, proofTarget{URL: origin.URL, Bytes: 128 * 1024, TLS: &tls.Config{RootCAs: roots}})
	select {
	case n := <-delayed:
		t.Logf("relay delayed one authentic short datagram: %d bytes", n)
	default:
		t.Fatal("fault not exercised")
	}
	if err != nil {
		t.Fatal(err)
	}
}
