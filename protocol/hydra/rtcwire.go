package hydra

// WebRTC wire primitives ported from the Rust reference (vpns/hydra
// src/wire.rs): SHA-1 / HMAC-SHA-1 / CRC-32 (FINGERPRINT), STUN message
// build+parse (RFC 5389), XOR-MAPPED-ADDRESS, and RTP/RTCP shapes. Byte
// formats are shape-faithful so a real ICE stack (or a DPI box) parses the
// packets as valid WebRTC traffic. All builders are checked byte-exact
// against testdata/rtc_vectors.txt in rtc_test.go.

import (
	"encoding/binary"
	"net/netip"
)

var stunMagic = [4]byte{0x21, 0x12, 0xA4, 0x42}

const (
	// StunHeaderLen is the fixed STUN header size (RFC 5389).
	StunHeaderLen = 20
)

// STUN message classes/types used by ICE connectivity checks.
const (
	stunBindingRequest  uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101
	stunBindingError    uint16 = 0x0111
)

// STUN attribute types (RFC 5389 + ICE RFC 8445).
const (
	attrMappedAddress    uint16 = 0x0001
	AttrUsername         uint16 = 0x0006
	AttrMessageIntegrity uint16 = 0x0008
	attrErrorCode        uint16 = 0x0009
	AttrXorMappedAddress uint16 = 0x0020
	AttrPriority         uint16 = 0x0024
	AttrSoftware         uint16 = 0x8022
	AttrFingerprint      uint16 = 0x8028
	AttrIceControlled    uint16 = 0x8029
	AttrIceControlling   uint16 = 0x802A
	// AttrOpaqueApp is a comprehension-optional experimental attribute
	// carrying opaque application bytes (hydra handshake payloads ride here;
	// DPI sees an unknown optional attribute).
	AttrOpaqueApp uint16 = 0xC055
)

// fingerprintXor is the CRC XOR mask ("STUN") from RFC 5389 §15.5.
const fingerprintXor uint32 = 0x5354554E

// RTP data-plane shape constants.
const (
	RTPHeaderLen = 12
	// RTPPtOpus is the Opus dynamic payload type (the one real WebRTC audio
	// flow uses).
	RTPPtOpus uint8 = 111
	// RTPPtFec is the ULPFEC-family dynamic payload type for parity
	// (repair) packets.
	RTPPtFec uint8 = 100
)

// ------------------------------------------------------------- SHA-1 ----

func rotl32(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }

// sha1Sum is a minimal SHA-1 (FIPS 180-1), used only for STUN
// MESSAGE-INTEGRITY shaping (ported line-for-line from wire.rs so the bytes
// match the Rust engine).
func sha1Sum(data []byte) [20]byte {
	h := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	bitlen := uint64(len(data)) * 8
	msg := make([]byte, 0, len(data)+72)
	msg = append(msg, data...)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	msg = binary.BigEndian.AppendUint64(msg, bitlen)

	for off := 0; off+64 <= len(msg); off += 64 {
		chunk := msg[off : off+64]
		var w [80]uint32
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(chunk[i*4:])
		}
		for i := 16; i < 80; i++ {
			w[i] = rotl32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}
		a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
		for i := 0; i < 80; i++ {
			var f, k uint32
			switch {
			case i < 20:
				f, k = (b&c)|(^b&d), 0x5A827999
			case i < 40:
				f, k = b^c^d, 0x6ED9EBA1
			case i < 60:
				f, k = (b&c)|(b&d)|(c&d), 0x8F1BBCDC
			default:
				f, k = b^c^d, 0xCA62C1D6
			}
			tmp := rotl32(a, 5) + f + e + k + w[i]
			e, d, c, b, a = d, c, rotl32(b, 30), a, tmp
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}
	var out [20]byte
	for i, word := range h {
		binary.BigEndian.PutUint32(out[i*4:], word)
	}
	return out
}

// hmacSHA1 is HMAC-SHA-1 (RFC 2104) with block size 64.
func hmacSHA1(key, data []byte) [20]byte {
	var k [64]byte
	if len(key) > 64 {
		sum := sha1Sum(key)
		copy(k[:20], sum[:])
	} else {
		copy(k[:], key)
	}
	ipad := [64]byte{}
	opad := [64]byte{}
	for i := 0; i < 64; i++ {
		ipad[i] = 0x36 ^ k[i]
		opad[i] = 0x5c ^ k[i]
	}
	inner := append(ipad[:], data...)
	ih := sha1Sum(inner)
	outer := append(opad[:], ih[:]...)
	return sha1Sum(outer)
}

// ------------------------------------------------------------- CRC32 ----

// crc32IEEE is CRC-32/ISO-HDLC (the polynomial STUN FINGERPRINT uses),
// reflected, init 0xFFFFFFFF, final XOR 0xFFFFFFFF.
func crc32IEEE(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			mask := -uint32(crc & 1) // wrapping negation
			crc = (crc >> 1) ^ (0xEDB88320 & mask)
		}
	}
	return ^crc
}

// --------------------------------------------------------------- STUN ----

// stunAttr is one TLV attribute value.
type stunAttr struct {
	Typ uint16
	Val []byte
}

// stunMessage is a parsed STUN message with attributes in wire order.
type stunMessage struct {
	MsgType uint16
	TxnID   [12]byte
	Attrs   []stunAttr
}

// stunBuild assembles a STUN message: header + attributes in order, appending
// MESSAGE-INTEGRITY (HMAC-SHA1 over everything before it) and FINGERPRINT
// when requested — exactly how a real ICE agent terminates its packets.
func stunBuild(msgType uint16, txnID [12]byte, attrs []stunAttr, integrityKey []byte, fingerprint bool) []byte {
	body := make([]byte, 0, 128)
	for _, a := range attrs {
		body = binary.BigEndian.AppendUint16(body, a.Typ)
		body = binary.BigEndian.AppendUint16(body, uint16(len(a.Val)))
		body = append(body, a.Val...)
		// Attribute values are padded to 4-byte boundaries (RFC 5389 §15).
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
	}
	if integrityKey != nil {
		// MESSAGE-INTEGRITY covers header + previous attributes with the
		// length field updated to end at the integrity attribute.
		miOffset := len(body)
		lenForMI := uint16(miOffset + 24)
		miInput := make([]byte, 0, StunHeaderLen+miOffset)
		miInput = binary.BigEndian.AppendUint16(miInput, msgType)
		miInput = binary.BigEndian.AppendUint16(miInput, lenForMI)
		miInput = append(miInput, stunMagic[:]...)
		miInput = append(miInput, txnID[:]...)
		miInput = append(miInput, body...)
		mac := hmacSHA1(integrityKey, miInput)
		body = binary.BigEndian.AppendUint16(body, AttrMessageIntegrity)
		body = binary.BigEndian.AppendUint16(body, 20)
		body = append(body, mac[:]...)
	}
	if fingerprint {
		fpOffset := len(body)
		lenForFP := uint16(fpOffset + 8)
		fpInput := make([]byte, 0, StunHeaderLen+fpOffset)
		fpInput = binary.BigEndian.AppendUint16(fpInput, msgType)
		fpInput = binary.BigEndian.AppendUint16(fpInput, lenForFP)
		fpInput = append(fpInput, stunMagic[:]...)
		fpInput = append(fpInput, txnID[:]...)
		fpInput = append(fpInput, body...)
		crc := crc32IEEE(fpInput) ^ fingerprintXor
		body = binary.BigEndian.AppendUint16(body, AttrFingerprint)
		body = binary.BigEndian.AppendUint16(body, 4)
		body = binary.BigEndian.AppendUint32(body, crc)
	}

	msg := make([]byte, 0, StunHeaderLen+len(body))
	msg = binary.BigEndian.AppendUint16(msg, msgType)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(body)))
	msg = append(msg, stunMagic[:]...)
	msg = append(msg, txnID[:]...)
	msg = append(msg, body...)
	return msg
}

// stunParse parses a STUN message strictly: correct magic cookie,
// length-consistent (nDPI's is_stun predicate), attributes well-formed and
// 4-byte aligned.
func stunParse(buf []byte) (stunMessage, bool) {
	if len(buf) < StunHeaderLen {
		return stunMessage{}, false
	}
	msgType := binary.BigEndian.Uint16(buf)
	msgLen := int(binary.BigEndian.Uint16(buf[2:4]))
	// RFC 5389: message length counts attributes, 4-byte aligned.
	if msgLen%4 != 0 || len(buf) != StunHeaderLen+msgLen {
		return stunMessage{}, false
	}
	if !bytesEqualConst(buf[4:8], stunMagic[:]) {
		return stunMessage{}, false
	}
	var m stunMessage
	m.MsgType = msgType
	copy(m.TxnID[:], buf[8:20])
	off := StunHeaderLen
	for off+4 <= len(buf) {
		at := binary.BigEndian.Uint16(buf[off:])
		al := int(binary.BigEndian.Uint16(buf[off+2:]))
		padded := ((al + 3) / 4) * 4
		if off+4+al > len(buf) {
			return stunMessage{}, false
		}
		m.Attrs = append(m.Attrs, stunAttr{Typ: at, Val: append([]byte{}, buf[off+4:off+4+al]...)})
		off += 4 + padded
	}
	if off != len(buf) {
		return stunMessage{}, false
	}
	return m, true
}

func bytesEqualConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// attr returns the first attribute value with the given type, or nil.
func (m stunMessage) attr(typ uint16) []byte {
	for i := range m.Attrs {
		if m.Attrs[i].Typ == typ {
			return m.Attrs[i].Val
		}
	}
	return nil
}

// verify checks FINGERPRINT (CRC32) and MESSAGE-INTEGRITY (HMAC-SHA1 over the
// packet up to the integrity attr) per RFC 5389 §10/§15. Ported from
// StunMessage::verify in wire.rs.
func (m stunMessage) verify(raw []byte, key []byte) bool {
	// FINGERPRINT (if present) is the last attribute. CRC input is the
	// message up to (not including) the FINGERPRINT attribute, with the
	// header length field rewritten to exclude it (RFC 5389 §15.5).
	if fp := m.attr(AttrFingerprint); fp != nil {
		if len(fp) != 4 {
			return false
		}
		expect := binary.BigEndian.Uint32(fp)
		fpPos, ok := findAttrOffset(raw, AttrFingerprint)
		if !ok {
			return false
		}
		input := append([]byte{}, raw[:fpPos]...)
		lenForFP := uint16(fpPos + 8 - StunHeaderLen)
		binary.BigEndian.PutUint16(input[2:4], lenForFP)
		if crc32IEEE(input)^fingerprintXor != expect {
			return false
		}
	}
	// MESSAGE-INTEGRITY: recompute HMAC over everything up to its own attr
	// with the length field rewritten to end at the integrity attribute.
	miPos, ok := findAttrOffset(raw, AttrMessageIntegrity)
	if !ok {
		return false
	}
	if miPos+24 > len(raw) {
		return false
	}
	input := append([]byte{}, raw[:miPos]...)
	lenForMI := uint16(miPos + 24 - StunHeaderLen)
	binary.BigEndian.PutUint16(input[2:4], lenForMI)
	mac := hmacSHA1(key, input)
	return bytesEqualConst(mac[:], raw[miPos+4:miPos+24])
}

// findAttrOffset returns the byte offset of an attribute's header within a
// raw STUN packet, or false when absent.
func findAttrOffset(raw []byte, attr uint16) (int, bool) {
	if len(raw) < StunHeaderLen {
		return 0, false
	}
	msgLen := int(binary.BigEndian.Uint16(raw[2:4]))
	end := StunHeaderLen + msgLen
	if end > len(raw) {
		end = len(raw)
	}
	off := StunHeaderLen
	for off+4 <= end {
		at := binary.BigEndian.Uint16(raw[off:])
		al := int(binary.BigEndian.Uint16(raw[off+2:]))
		if at == attr {
			return off, true
		}
		off += 4 + ((al+3)/4)*4
	}
	return 0, false
}

// xorMappedAddress encodes XOR-MAPPED-ADDRESS (RFC 5389 §15.2).
func xorMappedAddress(addr netip.Addr, port uint16) []byte {
	xport := port ^ 0x2112
	ip := addr.Unmap()
	var out []byte
	if ip.Is4() {
		oct := ip.As4()
		xip := binary.BigEndian.Uint32(oct[:]) ^ binary.BigEndian.Uint32(stunMagic[:])
		out = []byte{0, 0x01, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(out[2:4], xport)
		binary.BigEndian.PutUint32(out[4:8], xip)
	} else {
		oct := ip.As16()
		var raw [16]byte
		copy(raw[:], oct[:])
		var xip [16]byte
		for i := 0; i < 16; i++ {
			xip[i] = raw[i]
		}
		for i := 0; i < 4; i++ {
			xip[i] ^= stunMagic[i]
		}
		out = make([]byte, 20)
		out[1] = 0x02
		binary.BigEndian.PutUint16(out[2:4], xport)
		copy(out[4:20], xip[:])
	}
	return out
}

// parseXorMappedAddress decodes XOR-MAPPED-ADDRESS.
func parseXorMappedAddress(value []byte) (netip.Addr, uint16, bool) {
	if len(value) < 8 {
		return netip.Addr{}, 0, false
	}
	xport := binary.BigEndian.Uint16(value[2:4]) ^ 0x2112
	switch value[1] {
	case 0x01:
		x := binary.BigEndian.Uint32(value[4:8]) ^ binary.BigEndian.Uint32(stunMagic[:])
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], x)
		return netip.AddrFrom4(ip), xport, true
	case 0x02:
		if len(value) < 20 {
			return netip.Addr{}, 0, false
		}
		var xip [16]byte
		copy(xip[:], value[4:20])
		for i := 0; i < 4; i++ {
			xip[i] ^= stunMagic[i]
		}
		return netip.AddrFrom16(xip), xport, true
	default:
		return netip.Addr{}, 0, false
	}
}

// ------------------------------------------------------------ RTP/RTCP ----

// rtpHeader builds an RTP header (V=2, no padding/extension, 0 CSRC).
func rtpHeader(seq uint16, timestamp uint32, ssrc uint32, pt uint8) [RTPHeaderLen]byte {
	var h [RTPHeaderLen]byte
	h[0] = 0x80 // V=2, P=0, X=0, CC=0
	h[1] = pt & 0x7f
	binary.BigEndian.PutUint16(h[2:4], seq)
	binary.BigEndian.PutUint32(h[4:8], timestamp)
	binary.BigEndian.PutUint32(h[8:12], ssrc)
	return h
}

// isRTPorRTCP demuxes by the standard first-byte check.
func isRTPorRTCP(p []byte) bool {
	return len(p) >= 2 && p[0]&0xc0 == 0x80
}

// rtcpSR builds an RTCP sender-report-shaped keepalive. Padding reports
// follow the real 8-byte SR header; content rides encrypted inside the
// report body (rtc.rs truncates to the header before appending the sealed
// body, keeping the full-SR length word — ported verbatim).
func rtcpSR(ssrc uint32, ntpSeconds uint32, rtpTS uint32, packetCount uint32, octetCount uint32) []byte {
	m := make([]byte, 0, 28)
	m = append(m, 0x80, 200)
	m = binary.BigEndian.AppendUint16(m, 6) // length in 32-bit words minus 1
	m = binary.BigEndian.AppendUint32(m, ssrc)
	m = binary.BigEndian.AppendUint32(m, ntpSeconds)
	m = binary.BigEndian.AppendUint32(m, 0) // ntp fraction
	m = binary.BigEndian.AppendUint32(m, rtpTS)
	m = binary.BigEndian.AppendUint32(m, packetCount)
	m = binary.BigEndian.AppendUint32(m, octetCount)
	return m
}

// rtcpRR builds an RTCP receiver-report shape (the reliable layer's ACK
// carrier).
func rtcpRR(ssrc uint32, bodyWords uint16) []byte {
	m := make([]byte, 0, 8)
	m = append(m, 0x80, 201)
	m = binary.BigEndian.AppendUint16(m, bodyWords)
	m = binary.BigEndian.AppendUint32(m, ssrc)
	return m
}

// classifyPacket labels a packet for observability/tests: STUN / DTLS-shape /
// RTCP / SRTP / other (ported from wire.rs classify).
func classifyPacket(p []byte) string {
	if len(p) == 0 {
		return "other"
	}
	first := p[0]
	switch {
	case first <= 3:
		return "STUN"
	case first >= 20 && first <= 63:
		return "DTLS"
	case first&0xc0 == 0x80:
		if len(p) > 1 && p[1] >= 200 && p[1] <= 207 {
			return "RTCP"
		}
		return "SRTP"
	default:
		return "other"
	}
}
