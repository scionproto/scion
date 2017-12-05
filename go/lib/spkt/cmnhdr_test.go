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

package spkt

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
)

var cmnhInput = [CmnHdrLen]byte{0x01, 0xf8, 0x0c, 0xb6, 0x1f, 0xab, 0xcd, 0xef}

func Test_CmnHdr_Parse(t *testing.T) {
	Convey("CmnHdr.Parse should parse bytes correctly", t, func() {
		cmn := &CmnHdr{}
		So(cmn.Parse(cmnhInput[:]), ShouldEqual, nil)
		So(cmn.Ver, ShouldEqual, 0x0)
		So(cmn.DstType, ShouldEqual, 0x07)
		So(cmn.SrcType, ShouldEqual, 0x38)
		So(cmn.TotalLen, ShouldEqual, 0x0cb6)
		So(cmn.HdrLen, ShouldEqual, 0x1f)
		So(cmn.CurrInfoF, ShouldEqual, 0xab)
		So(cmn.CurrHopF, ShouldEqual, 0xcd)
		So(cmn.NextHdr, ShouldEqual, 0xef)
	})
	Convey("CmnHdr.Parse should report unsupported version", t, func() {
		cmn := &CmnHdr{}
		input := append([]byte(nil), cmnhInput[:]...)
		input[0] |= 0x30
		err := cmn.Parse(input)
		So(err, ShouldNotBeNil)
		cerr := err.(*common.CError)
		data, ok := cerr.Data.(*scmp.ErrData)
		So(ok, ShouldBeTrue)
		So(data.CT, ShouldResemble, scmp.ClassType{Class: scmp.C_CmnHdr, Type: scmp.T_C_BadVersion})
		So(cmn.Ver, ShouldEqual, 0x3)
	})
}

func Test_CmnHdr_Write(t *testing.T) {
	Convey("CmnHdr.Write should write bytes correctly", t, func() {
		cmn := &CmnHdr{
			Ver: 0x0, DstType: 0x07, SrcType: 0x38, TotalLen: 0x0cb6,
			HdrLen: 0x1f, CurrInfoF: 0xab, CurrHopF: 0xcd, NextHdr: 0xef,
		}
		out := make([]byte, CmnHdrLen)
		cmn.Write(out)
		So(out, ShouldResemble, cmnhInput[:])
	})
}

func Test_CmnHdr_UpdatePathOffsets(t *testing.T) {
	Convey("CmnHdr.UpdatePathOffsets should update values correctly", t, func() {
		cmn := &CmnHdr{}
		cmn.Parse(cmnhInput[:])
		out := make([]byte, CmnHdrLen)
		cmn.UpdatePathOffsets(out, 0x12, 0x23)
		So(out, ShouldResemble, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x23, 0x00})
		So(cmn.CurrInfoF, ShouldEqual, 0x12)
		So(cmn.CurrHopF, ShouldEqual, 0x23)
	})
}
