// Copyright 2017 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package util_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/util"
)

func TestChecksum(t *testing.T) {
	tests := []struct {
		Input  [][]byte
		Output [2]byte
	}{
		{[][]byte{{0x00, 0x01}}, [2]byte{0xff, 0xfe}},
		{[][]byte{{0x34, 0x88, 0x19, 0x55}}, [2]byte{0xb2, 0x22}},
		{[][]byte{{0x17, 0x00}}, [2]byte{0xe8, 0xff}},
		{[][]byte{{0x11, 0x11}}, [2]byte{0xee, 0xee}},
		{[][]byte{{0xef}}, [2]byte{0x10, 0xff}},
		{[][]byte{{0x11}, {0x80, 0x15, 0x13}},
			[2]byte{0x5b, 0xea}},
		{[][]byte{{0xa1, 0xa2, 0xa3, 0xa4},
			{0xb1, 0xb2, 0xb3},
			{0x10, 0x20}}, [2]byte{0x45, 0xe5}},
	}
	for _, test := range tests {
		checksum := make([]byte, 2)
		binary.BigEndian.PutUint16(checksum, util.Checksum(test.Input...))
		t.Run(fmt.Sprintf("Input %v", test.Input), func(t *testing.T) {
			assert.Equal(t, test.Output[:], checksum)
		})
	}
}

func BenchmarkChecksum(b *testing.B) {
	data := make([]byte, 1500)
	for i := 0; i < len(data); i++ {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		util.Checksum(data)
	}
}
