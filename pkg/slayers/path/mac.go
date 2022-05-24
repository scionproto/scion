// Copyright 2020 Anapaya Systems
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

package path

import (
	"encoding/binary"
	"hash"
)

const MACBufferSize = 16

// MAC calculates the HopField MAC according to
// https://docs.scion.org/en/latest/protocols/scion-header.html#hop-field-mac-computation
// this method does not modify info or hf.
// Modifying the provided buffer after calling this function may change the returned HopField MAC.
func MAC(h hash.Hash, info InfoField, hf HopField, buffer []byte) [MacLen]byte {
	mac := FullMAC(h, info, hf, buffer)
	var res [MacLen]byte
	copy(res[:], mac[:MacLen])
	return res
}

// FullMAC calculates the HopField MAC according to
// https://docs.scion.org/en/latest/protocols/scion-header.html#hop-field-mac-computation
// this method does not modify info or hf.
// Modifying the provided buffer after calling this function may change the returned HopField MAC.
// In contrast to MAC(), FullMAC returns all the 16 bytes instead of only 6 bytes of the MAC.
func FullMAC(h hash.Hash, info InfoField, hf HopField, buffer []byte) []byte {
	if len(buffer) < MACBufferSize {
		buffer = make([]byte, MACBufferSize)
	}

	h.Reset()
	MACInput(info.SegID, info.Timestamp, hf.ExpTime,
		hf.ConsIngress, hf.ConsEgress, buffer)
	// Write must not return an error: https://godoc.org/hash#Hash
	if _, err := h.Write(buffer); err != nil {
		panic(err)
	}
	return h.Sum(buffer[:0])[:16]
}

// MACInput returns the MAC input data block with the following layout:
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |               0               |             SegID             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           Timestamp                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       0       |    ExpTime    |          ConsIngress          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          ConsEgress           |               0               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
func MACInput(segID uint16, timestamp uint32, expTime uint8,
	consIngress, consEgress uint16, buffer []byte) {

	binary.BigEndian.PutUint16(buffer[0:2], 0)
	binary.BigEndian.PutUint16(buffer[2:4], segID)
	binary.BigEndian.PutUint32(buffer[4:8], timestamp)
	buffer[8] = 0
	buffer[9] = expTime
	binary.BigEndian.PutUint16(buffer[10:12], consIngress)
	binary.BigEndian.PutUint16(buffer[12:14], consEgress)
	binary.BigEndian.PutUint16(buffer[14:16], 0)
}
