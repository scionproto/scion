// Copyright 2026 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package checksum implements the Internet ones-complement checksum
// (RFC 1071, https://www.rfc-editor.org/rfc/rfc1071) for IPv4 headers and
// IPv6/UDP packets, specialized for the afxdpudpip underlay TX hot path.
//
// The ones-complement sum is commutative and associative over 16-bit words in
// network byte order, so we accumulate wider chunks (uint32 read big-endian)
// into a uint64 and fold once at the end. Summing a big-endian uint32 is
// equivalent to summing its two 16-bit halves once the final fold collapses
// carries from bits 16..31 back into bits 0..15.
package checksum

import "encoding/binary"

// udpProto is the UDP Next-Header / Protocol value
// (See https://www.rfc-editor.org/rfc/rfc768#page-3).
const udpProto = 17

// IPv4Header returns the ones-complement checksum of a 20-byte IPv4 header
// (See https://www.rfc-editor.org/rfc/rfc791#section-3.1). The checksum field
// in the header must be zeroed by the caller before the call.
func IPv4Header(h []byte) uint16 {
	_ = h[19] // bounds-check elimination
	var s uint64
	s += uint64(binary.BigEndian.Uint32(h[0:4]))
	s += uint64(binary.BigEndian.Uint32(h[4:8]))
	s += uint64(binary.BigEndian.Uint32(h[8:12]))
	s += uint64(binary.BigEndian.Uint32(h[12:16]))
	s += uint64(binary.BigEndian.Uint32(h[16:20]))
	return ^fold(s)
}

// UDP6Pseudo returns the ones-complement partial sum of the IPv6/UDP pseudo
// header (See https://www.rfc-editor.org/rfc/rfc8200#section-8.1):
// srcIP || dstIP || udpLen || 0x000000 || nextHdr=17.
// The result is the NON-inverted partial sum — the caller (or NIC, when
// offloading via AF_XDP XDP_TXMD_FLAGS_CHECKSUM) adds the remaining bytes and
// finalizes with ones-complement inversion.
func UDP6Pseudo(srcIP, dstIP [16]byte, udpLen int) uint16 {
	s := sumFixed16(srcIP) + sumFixed16(dstIP)
	s += uint64(uint32(udpLen))
	s += udpProto
	return fold(s)
}

// UDP6 returns the UDP checksum over the IPv6 pseudo-header, UDP header, and
// payload (See https://www.rfc-editor.org/rfc/rfc8200#section-8.1). The UDP
// checksum field in udpHdr must be zeroed before the call. A computed value
// of 0x0000 is returned as 0xFFFF per https://www.rfc-editor.org/rfc/rfc8200#section-8.1
// (0 means "no checksum" only for IPv4 UDP).
func UDP6(srcIP, dstIP [16]byte, udpHdr, payload []byte) uint16 {
	s := sumFixed16(srcIP) + sumFixed16(dstIP)
	s += uint64(uint32(len(udpHdr) + len(payload)))
	s += udpProto
	s += sum(udpHdr)
	s += sum(payload)
	csum := ^fold(s)
	if csum == 0 {
		csum = 0xFFFF
	}
	return csum
}

// sumFixed16 returns the partial sum of a fixed 16-byte block
// (e.g. an IPv6 address) as four big-endian uint32 loads.
func sumFixed16(b [16]byte) uint64 {
	return uint64(binary.BigEndian.Uint32(b[0:4])) +
		uint64(binary.BigEndian.Uint32(b[4:8])) +
		uint64(binary.BigEndian.Uint32(b[8:12])) +
		uint64(binary.BigEndian.Uint32(b[12:16]))
}

// sum returns the unfolded ones-complement partial sum of data treated as a
// sequence of 16-bit big-endian words. An odd trailing byte is zero-padded on
// the right, i.e. treated as the high byte of a 16-bit word.
func sum(data []byte) uint64 {
	var s uint64
	// 32-byte unrolled loop: 8 uint32 loads per iteration to expose ILP.
	for len(data) >= 32 {
		s += uint64(binary.BigEndian.Uint32(data[0:4]))
		s += uint64(binary.BigEndian.Uint32(data[4:8]))
		s += uint64(binary.BigEndian.Uint32(data[8:12]))
		s += uint64(binary.BigEndian.Uint32(data[12:16]))
		s += uint64(binary.BigEndian.Uint32(data[16:20]))
		s += uint64(binary.BigEndian.Uint32(data[20:24]))
		s += uint64(binary.BigEndian.Uint32(data[24:28]))
		s += uint64(binary.BigEndian.Uint32(data[28:32]))
		data = data[32:]
	}
	for len(data) >= 4 {
		s += uint64(binary.BigEndian.Uint32(data[0:4]))
		data = data[4:]
	}
	if len(data) >= 2 {
		s += uint64(binary.BigEndian.Uint16(data[0:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		s += uint64(data[0]) << 8
	}
	return s
}

// fold collapses a 64-bit accumulator of 16-bit-word partial sums into a single
// 16-bit ones-complement result. Each reduction step adds overflow carries back into
// the low 16 bits; three steps are sufficient for any uint64 input.
func fold(s uint64) uint16 {
	s = (s & 0xFFFFFFFF) + (s >> 32)
	s = (s & 0xFFFF) + (s >> 16)
	s = (s & 0xFFFF) + (s >> 16)
	return uint16(s)
}
