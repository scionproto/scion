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
	"github.com/netsec-ethz/scion/go/lib/common"
)

// Calculate RFC1071 checksum of supplied data chunks. If a chunk has
// an odd length, it is padded with a 0 during checksum computation.
func Checksum(srcs ...common.RawBytes) uint16 {
	var sum uint32
	for _, src := range srcs {
		length := len(src)
		i := 0

		if length == 0 {
			continue
		}
		for ; i < length-1; i += 2 {
			sum += toUint32(src[i], src[i+1])
		}
		if i != length {
			sum += toUint32(src[i], 0)
		}
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func toUint32(x uint8, y uint8) uint32 {
	return uint32(x)<<8 + uint32(y)
}
