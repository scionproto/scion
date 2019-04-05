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
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

type pathCase struct {
	consDir bool
	hops    []uint8
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
					SoMsg(prefix+" InfoF consDir", infof.ConsDir, ShouldEqual, out.consDir)
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
		makeSeg(path.Raw[offset:], seg.consDir, uint16(i), seg.hops)
		offset += InfoFieldLength + len(seg.hops)*HopFieldLength
	}
	return path
}

func makeSeg(b common.RawBytes, consDir bool, isd uint16, hops []uint8) {
	infof := InfoField{ConsDir: consDir, ISD: isd, Hops: uint8(len(hops))}
	infof.Write(b)
	for i, hop := range hops {
		for j := 0; j < HopFieldLength; j++ {
			b[InfoFieldLength+i*HopFieldLength+j] = hop
		}
	}
}

func TestNewOneHop(t *testing.T) {
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	// Compute the correct tag for the first hop field.
	tag, err := (&HopField{ConsEgress: 11, ExpTime: 4}).CalcMac(mac, 3, nil)
	xtest.FailOnErr(t, err)
	mac.Reset()

	Convey("The one hop path should be created correctly", t, func() {
		p, err := NewOneHop(1, 11, util.SecsToTime(3), 4, mac)
		SoMsg("err", err, ShouldBeNil)
		err = p.InitOffsets()
		SoMsg("InitOffsets", err, ShouldBeNil)
		// Check the info field is set correctly.
		info, err := p.GetInfoField(p.InfOff)
		SoMsg("GetInfoField", err, ShouldBeNil)
		Convey("The info field is correct", func() {
			SoMsg("ConsDir", info.ConsDir, ShouldBeTrue)
			SoMsg("Shortcut", info.Shortcut, ShouldBeFalse)
			SoMsg("Peer", info.Peer, ShouldBeFalse)
			SoMsg("TsInt", info.TsInt, ShouldEqual, 3)
			SoMsg("ISD", info.ISD, ShouldEqual, 1)
			SoMsg("Hops", info.Hops, ShouldEqual, 2)
		})
		// Check the first hop field is set correctly.
		hop, err := p.GetHopField(p.HopOff)
		SoMsg("GetHopField", err, ShouldBeNil)
		Convey("The first hop field is correct", func() {
			SoMsg("Xover", hop.Xover, ShouldBeFalse)
			SoMsg("VerifyOnly", hop.VerifyOnly, ShouldBeFalse)
			SoMsg("ExpTime", hop.ExpTime, ShouldEqual, 4)
			SoMsg("ConsIngress", hop.ConsIngress, ShouldEqual, 0)
			SoMsg("ConsEgress", hop.ConsEgress, ShouldEqual, 11)
			SoMsg("Mac", hop.Mac, ShouldResemble, tag[:MacLen])
		})
		// Check the path has two hop fields.
		oldInfoOff := p.InfOff
		err = p.IncOffsets()
		SoMsg("IncOffsets", err, ShouldBeNil)
		SoMsg("Same info field", p.InfOff, ShouldEqual, oldInfoOff)
		// Check the second hop field is empty.
		hop, err = p.GetHopField(p.HopOff)
		SoMsg("GetHopField", err, ShouldBeNil)
		Convey("The second hop field is empty", func() {
			SoMsg("hop", hop, ShouldResemble, &HopField{Mac: common.RawBytes{0, 0, 0}})
		})
	})
}
