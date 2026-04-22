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

package checksum

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

var payloadSizes = []struct {
	name string
	size int
}{
	{"172B", 172},
	{"508B", 508},
	{"1200B", 1200},
	{"1452B", 1452},
	{"9000B", 9000},
}

// ---------------- IPv4 header ----------------

func BenchmarkIPv4Header(b *testing.B) {
	hdr := make([]byte, 20)
	rand.Read(hdr)
	naive := func(header []byte) uint16 {
		var sum uint32
		for i := 0; i+1 < len(header); i += 2 {
			sum += uint32(header[i])<<8 | uint32(header[i+1])
		}
		if len(header)%2 != 0 {
			sum += uint32(header[len(header)-1]) << 8
		}
		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
		return ^uint16(sum)
	}
	b.Run("naive", func(b *testing.B) {
		b.SetBytes(int64(len(hdr)))
		for b.Loop() {
			hdr[10], hdr[11] = 0, 0
			binary.BigEndian.PutUint16(hdr[10:12], naive(hdr))
		}
	})
	b.Run("fast", func(b *testing.B) {
		b.SetBytes(int64(len(hdr)))
		for b.Loop() {
			hdr[10], hdr[11] = 0, 0
			binary.BigEndian.PutUint16(hdr[10:12], IPv4Header(hdr))
		}
	})
}

// ---------------- IPv6 UDP full checksum (software fallback) ----------------

func BenchmarkUDP6(b *testing.B) {
	naive := func(srcIP, dstIP [16]byte, udpHdr, payload []byte) uint16 {
		var sum uint32
		for i := 0; i < 16; i += 2 {
			sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
		}
		for i := 0; i < 16; i += 2 {
			sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
		}
		sum += uint32(len(udpHdr) + len(payload))
		sum += 17
		for i := 0; i+1 < len(udpHdr); i += 2 {
			sum += uint32(udpHdr[i])<<8 | uint32(udpHdr[i+1])
		}
		if len(udpHdr)%2 != 0 {
			sum += uint32(udpHdr[len(udpHdr)-1]) << 8
		}
		for i := 0; i+1 < len(payload); i += 2 {
			sum += uint32(payload[i])<<8 | uint32(payload[i+1])
		}
		if len(payload)%2 != 0 {
			sum += uint32(payload[len(payload)-1]) << 8
		}
		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
		csum := ^uint16(sum)
		if csum == 0 {
			csum = 0xFFFF
		}
		return csum
	}
	for _, ps := range payloadSizes {
		b.Run(ps.name, func(b *testing.B) {
			var srcIP, dstIP [16]byte
			rand.Read(srcIP[:])
			rand.Read(dstIP[:])
			udpHdr := make([]byte, 8)
			binary.BigEndian.PutUint16(udpHdr[0:2], 50000)
			binary.BigEndian.PutUint16(udpHdr[2:4], 50001)
			binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+ps.size))
			payload := make([]byte, ps.size)
			rand.Read(payload)

			total := int64(40 + 8 + ps.size)
			b.Run("naive", func(b *testing.B) {
				b.SetBytes(total)
				for b.Loop() {
					udpHdr[6], udpHdr[7] = 0, 0
					binary.BigEndian.PutUint16(udpHdr[6:8],
						naive(srcIP, dstIP, udpHdr, payload))
				}
			})
			b.Run("fast", func(b *testing.B) {
				b.SetBytes(total)
				for b.Loop() {
					udpHdr[6], udpHdr[7] = 0, 0
					binary.BigEndian.PutUint16(udpHdr[6:8],
						UDP6(srcIP, dstIP, udpHdr, payload))
				}
			})
		})
	}
}

// ---------------- IPv6 UDP pseudo-header only (NIC offload path) ----------------

func BenchmarkUDP6Pseudo(b *testing.B) {
	var srcIP, dstIP [16]byte
	rand.Read(srcIP[:])
	rand.Read(dstIP[:])
	const udpLen = 1208
	naive := func(srcIP, dstIP [16]byte, udpLen int) uint16 {
		var sum uint32
		for i := 0; i < 16; i += 2 {
			sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
		}
		for i := 0; i < 16; i += 2 {
			sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
		}
		sum += uint32(udpLen)
		sum += 17
		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
		return uint16(sum)
	}

	b.Run("naive", func(b *testing.B) {
		b.SetBytes(40)
		for b.Loop() {
			_ = naive(srcIP, dstIP, udpLen)
		}
	})
	b.Run("fast", func(b *testing.B) {
		b.SetBytes(40)
		for b.Loop() {
			_ = UDP6Pseudo(srcIP, dstIP, udpLen)
		}
	})
}
