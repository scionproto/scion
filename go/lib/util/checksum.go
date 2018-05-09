// Copyright 2017 ETH Zurich
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

package util

import (
	"unsafe"

	"github.com/scionproto/scion/go/lib/common"
)

// Calculate RFC1071 checksum of supplied data chunks. If a chunk has
// an odd length, it is padded with a 0 during checksum computation.
func Checksum(srcs ...common.RawBytes) uint16 {
	var sum uint32
	for _, src := range srcs {
		length := len(src)
		if length == 0 {
			continue
		}
		length2 := length / 2
		// XXX(kormat): this creates a uint16 slice pointing to the underlying
		// data in src. This provides a 2x speed-up, at least on
		// linux/{amd64,arm64}. How it works:
		// 1. Get the address of the backing array in src.
		// 2. Cast the address to a uint16 _array_ (with a size guaranteed to
		//    be large enough).
		// 3. Convert the array to a []uint16 of the appropriate number of
		//    uint16 elements (setting both length and cap).
		// This has to be converted via an array, so that new slice metadata is
		// allocated. Referencing a []uint8 as []uint16 will cause a crash.
		src16 := (*[1 << 16]uint16)(unsafe.Pointer(&src[0]))[:length2:length2]
		for i := 0; i < length2; i++ {
			sum += uint32(src16[i])
		}
		if length%2 != 0 {
			sum += uint32(src[length-1])
		}
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	if !common.IsBigEndian {
		// Native order is little-endian, so swap the bytes.
		sum = (sum&0xFF)<<8 + (sum >> 8)
	}
	return ^uint16(sum)
}
