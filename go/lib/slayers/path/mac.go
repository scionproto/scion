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
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/scionproto/scion/go/lib/serrors"
)

// MAC calculates the HopField MAC according to
// https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html#hop-field-mac-computation
// this method does not modify info or hf.
func MAC(h hash.Hash, info *InfoField, hf *HopField) []byte {
	h.Reset()
	input := macInput(info, hf)
	// Write must not return an error: https://godoc.org/hash#Hash
	if _, err := h.Write(input); err != nil {
		panic(err)
	}
	return h.Sum(nil)[:6]
}

// VerifyMAC verifies that the MAC in the hop field is correct, i.e. matches the
// value calculated with MAC(h, info, hf). If the calculated MAC matches the
// value in the hop field nil is returned, otherwise an error is returned.
func VerifyMAC(h hash.Hash, info *InfoField, hf *HopField) error {
	expectedMac := MAC(h, info, hf)
	if !bytes.Equal(hf.Mac, expectedMac) {
		return serrors.New("MAC",
			"expected", fmt.Sprintf("%x", expectedMac),
			"actual", fmt.Sprintf("%x", hf.Mac))
	}
	return nil
}

func macInput(info *InfoField, hf *HopField) []byte {
	input := make([]byte, 16)
	binary.BigEndian.PutUint32(input[:4], info.Timestamp)
	input[4] = hf.ExpTime
	binary.BigEndian.PutUint16(input[5:7], hf.ConsIngress)
	binary.BigEndian.PutUint16(input[7:9], hf.ConsEgress)
	binary.BigEndian.PutUint16(input[9:11], info.SegID)
	return input
}
