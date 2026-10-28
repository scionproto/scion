// Copyright 2026 Johnny Kao
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

package dataplane

import (
	"encoding/binary"
	"hash/crc64"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TestHashQuintuple checks the encoded 5-tuple and path hash contract without
// comparing against the production function's implementation.
func TestHashQuintuple(t *testing.T) {
	for _, tc := range []struct {
		name  string
		v6    bool
		proto byte
	}{
		{"ipv4_tcp", false, 6},
		{"ipv4_udp", false, 17},
		{"ipv4_other", false, 1},
		{"ipv6_tcp", true, 6},
		{"ipv6_udp", true, 17},
		{"ipv6_other", true, 58},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headerLen := 20
			payloadLen := 0
			if tc.v6 {
				headerLen = 40
			}
			switch tc.proto {
			case 6:
				payloadLen = 20
			case 17:
				payloadLen = 8
			}
			for n := 0; n < 1024; n++ {
				b := make([]byte, headerLen+payloadLen)
				expected := []byte{tc.proto}
				first := layers.LayerTypeIPv4
				if tc.v6 {
					first = layers.LayerTypeIPv6
					b[0], b[6], b[7] = 0x60, tc.proto, 64
					binary.BigEndian.PutUint16(b[4:6], uint16(payloadLen))
					for i := 0; i < 16; i++ {
						b[8+i], b[24+i] = byte(i+n), byte(255-i-n)
					}
					expected = append(expected, b[8:40]...)
				} else {
					b[0], b[8], b[9] = 0x45, 64, tc.proto
					binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
					for i := 0; i < 4; i++ {
						b[12+i], b[16+i] = byte(i+n), byte(255-i-n)
					}
					expected = append(expected, b[12:20]...)
				}
				if payloadLen > 0 {
					srcPort, dstPort := uint16(1024+n), uint16(443+n)
					binary.BigEndian.PutUint16(b[headerLen:headerLen+2], srcPort)
					binary.BigEndian.PutUint16(b[headerLen+2:headerLen+4], dstPort)
					if tc.proto == 6 {
						b[headerLen+12] = 0x50
					} else {
						binary.BigEndian.PutUint16(b[headerLen+4:headerLen+6], uint16(payloadLen))
					}
					expected = binary.BigEndian.AppendUint16(expected, srcPort)
					expected = binary.BigEndian.AppendUint16(expected, dstPort)
				}
				packet := gopacket.NewPacket(b, first, gopacket.DecodeOptions{NoCopy: true})
				if packet.NetworkLayer() == nil {
					t.Fatalf("invalid packet fixture n=%d", n)
				}
				got := hashQuintuple(packet)
				want := crc64.Checksum(expected, crcTable)
				if got != want {
					t.Fatalf("n=%d got=%x want=%x", n, got, want)
				}
				for _, paths := range []uint64{2, 4, 8} {
					if got%paths != want%paths {
						t.Fatalf("n=%d path selection mismatch", n)
					}
				}
			}
		})
	}
}
