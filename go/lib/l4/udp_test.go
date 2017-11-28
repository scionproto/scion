// Copyright 2017 Audrius Meskauskas with all possible permissions granted
// to ETH Zurich and Anapaya Systems
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

package l4

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/common"
)

// Create UDP structure
func createUDP() UDP {
	// Use hex, easier seen in binary dump
	return UDP{0x1234, 0x5678, 0xA, make(common.RawBytes, 2)}
}

func Test_UDPFromRaw(t *testing.T) {
	raw := common.RawBytes{
		0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0}
	fromRaw, err := UDPFromRaw(raw)

	original := createUDP()

	Convey("Content must match", t, func() {
		So(err, ShouldBeNil)
		So(fromRaw, ShouldResemble, &original)
	})
}

func Test_Validate(t *testing.T) {
	u := createUDP()

	Convey("It is structure of size 10, must be ok", t, func() {
		So(u.TotalLen, ShouldEqual, 10)
		err := u.Validate(int(u.TotalLen) - UDPLen)
		So(err, ShouldBeNil)
	})
}

func Test_Parse(t *testing.T) {
	// assuming we have tested UDPFromRaw
	u := createUDP()
	raw, err := u.Pack(true)

	u2 := UDP{0, 0, 0xA,
		make(common.RawBytes, 2)}
	u2.Parse(raw)

	Convey("Must parse into the same representation", t, func() {
		So(err, ShouldBeNil)
		So(u2, ShouldResemble, u)
	})
}

func Test_Pack(t *testing.T) {
	u := createUDP()
	raw, err := u.Pack(true)

	Convey("Binary content must match", t, func() {
		So(err, ShouldBeNil)
		So(raw.String(), ShouldEqual, "12345678000a0000")
		So(raw, ShouldResemble, common.RawBytes{
			0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0})
	})
}

func Test_Write(t *testing.T) {
	u := createUDP()
	raw := make(common.RawBytes, 8)
	err := u.Write(raw)

	Convey("Binary content must match", t, func() {
		So(err, ShouldBeNil)
		So(raw, ShouldResemble, common.RawBytes{
			0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0})
	})
}

func Test_Checksum(t *testing.T) {
	u := createUDP()

	Convey("Checksum field access", t, func() {
		So(u.GetCSum(), ShouldResemble, common.RawBytes{0, 0})
		u.SetCSum(common.RawBytes{1, 2})
		So(u.GetCSum(), ShouldResemble, common.RawBytes{1, 2})
	})
}

func Test_PldLen(t *testing.T) {
	u := createUDP()

	Convey("Checksum field access", t, func() {
		u.SetPldLen(11)
		So(u.TotalLen, ShouldEqual, UDPLen+11)
	})
}

func Test_Copy(t *testing.T) {
	u := createUDP()
	clone := u.Copy()

	Convey("Cloned instance must be equal but without checksum", t, func() {
		So(&u, ShouldResemble, clone)
	})
}

func Test_Reverse(t *testing.T) {
	u := createUDP()
	original := u

	u.Reverse()

	Convey("Ports must be swapped, size remain", t, func() {
		So(u.DstPort, ShouldEqual, original.SrcPort)
		So(u.SrcPort, ShouldEqual, original.DstPort)
		So(u.TotalLen, ShouldEqual, original.TotalLen)
	})
}

func Test_String(t *testing.T) {
	u := createUDP()
	string := u.String()

	Convey("String representation must match", t, func() {
		So(string,
			ShouldEqual, "SPort=4660 DPort=22136 TotalLen=10 Checksum=0000")
	})
}
