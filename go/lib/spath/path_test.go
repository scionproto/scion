// Copyright 2016 ETH Zurich
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

package spath

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
)

type pathCase struct {
	up   bool
	hops []uint8
}

var pathReverseCases = []struct {
	in      []pathCase
	out     []pathCase
	inOffs  [][2]int
	outOffs [][2]int
}{
	// 1 segment, 2 hops
	{
		[]pathCase{{true, []uint8{11, 12}}},
		[]pathCase{{false, []uint8{12, 11}}},
		[][2]int{{0, 8}, {0, 16}},
		[][2]int{{0, 16}, {0, 8}},
	},
	// 1 segment, 5 hops
	{
		[]pathCase{{true, []uint8{11, 12, 13, 14, 15}}},
		[]pathCase{{false, []uint8{15, 14, 13, 12, 11}}},
		[][2]int{{0, 8}, {0, 16}, {0, 24}, {0, 32}, {0, 40}},
		[][2]int{{0, 40}, {0, 32}, {0, 24}, {0, 16}, {0, 8}},
	},
	// 2 segments, 5 hops
	{
		[]pathCase{{true, []uint8{11, 12}}, {false, []uint8{13, 14, 15}}},
		[]pathCase{{true, []uint8{15, 14, 13}}, {false, []uint8{12, 11}}},
		[][2]int{{0, 8}, {0, 16}, {24, 32}, {24, 40}, {24, 48}},
		[][2]int{{32, 48}, {32, 40}, {0, 24}, {0, 16}, {0, 8}},
	},
	// 3 segments, 9 hops
	{
		[]pathCase{
			{true, []uint8{11, 12}},
			{false, []uint8{13, 14, 15, 16}},
			{false, []uint8{17, 18, 19}},
		},
		[]pathCase{
			{true, []uint8{19, 18, 17}},
			{true, []uint8{16, 15, 14, 13}},
			{false, []uint8{12, 11}},
		},
		[][2]int{
			{0, 8}, {0, 16}, {24, 32}, {24, 40}, {24, 48}, {24, 56}, {64, 72}, {64, 80}, {64, 88},
		},
		[][2]int{
			{72, 88}, {72, 80}, {32, 64}, {32, 56}, {32, 48}, {32, 40}, {0, 24}, {0, 16}, {0, 8},
		},
	},
}

func Test_Path_Reverse(t *testing.T) {
	for i, c := range pathReverseCases {
		for j := range c.outOffs {
			path := mkPathRevCase(c.in, c.inOffs[j][0], c.inOffs[j][1])
			desc := fmt.Sprintf("Path.Reverse() case %v infoF %v hopF %v",
				i, path.InfOff, path.HopOff)
			Convey(desc, t, func() {
				So(path.Reverse(), ShouldBeNil)
				offset := 0
				for seg := range c.in {
					out := c.out[seg]
					prefix := fmt.Sprintf("seg %d", seg)
					infof, err := InfoFFromRaw(path.Raw[offset:])
					SoMsg(prefix+" InfoF parse", err, ShouldBeNil)
					SoMsg(prefix+" InfoF up", infof.Up, ShouldEqual, out.up)
					SoMsg(prefix+" InfoF ISD "+infof.String(),
						infof.ISD, ShouldEqual, len(c.in)-seg-1)
					SoMsg(prefix+" InfoF Offset", path.InfOff, ShouldEqual, c.outOffs[j][0])
					SoMsg(prefix+" HopF Offset", path.HopOff, ShouldEqual, c.outOffs[j][1])
					for h, hop := range out.hops {
						for b := 0; b < HopFieldLength; b++ {
							msg := prefix + fmt.Sprintf(" hop %d byte %d", h, b)
							SoMsg(msg, path.Raw[offset+InfoFieldLength+h*HopFieldLength+b],
								ShouldEqual, hop)
						}
					}
					offset += InfoFieldLength + len(out.hops)*HopFieldLength
				}
			})
		}
	}
}

func mkPathRevCase(in []pathCase, inInfOff, inHopfOff int) *Path {
	path := &Path{InfOff: inInfOff, HopOff: inHopfOff}
	plen := 0
	for _, seg := range in {
		plen += InfoFieldLength + len(seg.hops)*HopFieldLength
	}
	path.Raw = make(common.RawBytes, plen)
	offset := 0
	for i, seg := range in {
		makeSeg(path.Raw[offset:], seg.up, uint16(i), seg.hops)
		offset += InfoFieldLength + len(seg.hops)*HopFieldLength
	}
	return path
}

func makeSeg(b common.RawBytes, up bool, isd uint16, hops []uint8) {
	infof := InfoField{Up: up, ISD: isd, Hops: uint8(len(hops))}
	infof.Write(b)
	for i, hop := range hops {
		for j := 0; j < HopFieldLength; j++ {
			b[InfoFieldLength+i*HopFieldLength+j] = hop
		}
	}
}
