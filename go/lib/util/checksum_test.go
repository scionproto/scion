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
	"encoding/binary"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
)

func TestChecksum(t *testing.T) {
	tests := []struct {
		Input  []common.RawBytes
		Output [2]byte
	}{
		{[]common.RawBytes{{0x00, 0x01}}, [2]byte{0xff, 0xfe}},
		{[]common.RawBytes{{0x34, 0x88, 0x19, 0x55}}, [2]byte{0xb2, 0x22}},
		{[]common.RawBytes{{0x17, 0x00}}, [2]byte{0xe8, 0xff}},
		{[]common.RawBytes{{0x11, 0x11}}, [2]byte{0xee, 0xee}},
		{[]common.RawBytes{{0xef}}, [2]byte{0x10, 0xff}},
		{[]common.RawBytes{{0x11}, {0x80, 0x15, 0x13}},
			[2]byte{0x5b, 0xea}},
		{[]common.RawBytes{{0xa1, 0xa2, 0xa3, 0xa4},
			{0xb1, 0xb2, 0xb3},
			{0x10, 0x20}}, [2]byte{0x45, 0xe5}},
	}

	Convey("Test checksum", t, func() {
		for _, test := range tests {
			checksum := make([]byte, 2)
			binary.BigEndian.PutUint16(checksum, Checksum(test.Input...))
			Convey(fmt.Sprintf("Input %v", test.Input), func() {
				So(checksum[0], ShouldEqual, test.Output[0])
				So(checksum[1], ShouldEqual, test.Output[1])
			})
		}
	})
}

func BenchmarkChecksum(b *testing.B) {
	data := make(common.RawBytes, 1500)
	for i := 0; i < len(data); i++ {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Checksum(data)
	}
}
