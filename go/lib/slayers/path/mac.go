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

// MAC calculates the HopField MAC according to
// https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html#hop-field-mac-computation
// this method does not modify info or hf.
func MAC(h hash.Hash, info *InfoField, hf *HopField) []byte {
	return FullMAC(h, info, hf)[:6]
}

// FullMAC calculates the HopField MAC according to
// https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html#hop-field-mac-computation
// this method does not modify info or hf.
// In contrast to MAC(), FullMAC returns all the 16 bytes instead of only 6 bytes of the MAC.
func FullMAC(h hash.Hash, info *InfoField, hf *HopField) []byte {
	h.Reset()
	input := MACInput(info.SegID, info.Timestamp, hf.ExpTime, hf.ConsIngress, hf.ConsEgress)
	// Write must not return an error: https://godoc.org/hash#Hash
	if _, err := h.Write(input); err != nil {
		panic(err)
	}
	return h.Sum(nil)[:16]
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
	consIngress, consEgress uint16) []byte {

	input := make([]byte, 16)
	binary.BigEndian.PutUint16(input[2:4], segID)
	binary.BigEndian.PutUint32(input[4:8], timestamp)
	input[9] = expTime
	binary.BigEndian.PutUint16(input[10:12], consIngress)
	binary.BigEndian.PutUint16(input[12:14], consEgress)
	return input
}
