// Copyright 2023 SCION Association
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

package cases

import (
	"github.com/google/gopacket"
)

// We make the assumption os protocol sanity: the length and checksum fields are of fixed size
// and so do not affect the packet size.
var hdrOptions = gopacket.SerializeOptions{
	FixLengths:       false,
	ComputeChecksums: false,
}

func headerLength(layers ...gopacket.SerializableLayer) int {
	sb := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(sb, hdrOptions, layers...); err != nil {
		panic(err)
	}
	return len(sb.Bytes())
}

func mkPayload(payloadLen int) []byte {
	if payloadLen < 0 {
		payloadLen = 0
	}
	payload := make([]byte, payloadLen)
	copy(payload[:], []byte("actualpayloadbytes"))
	return gopacket.Payload(payload)
}

var pktOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

func mkPacket(
	packetSize int,
	layers ...gopacket.SerializableLayer,
) ([]byte, []byte) {

	// We want to make a packet of a specific length, header included.
	hdrLen := headerLength(layers...)
	sb := gopacket.NewSerializeBuffer()
	payload := mkPayload(packetSize - hdrLen)
	err := gopacket.SerializeLayers(sb, pktOptions, append(layers, gopacket.Payload(payload))...)
	if err != nil {
		panic(err)
	}
	return payload, sb.Bytes()
}
