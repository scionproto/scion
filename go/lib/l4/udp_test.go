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

	"github.com/scionproto/scion/go/lib/common"
)

// Create UDP structure
func createUDP() UDP {
	// Use hex, easier seen in binary dump
	return UDP{0x1234, 0x5678, 0xA, make(common.RawBytes, 2)}
}

func TestUDPFromRaw(t *testing.T) {
	Convey("Content must match", t, func() {
		raw := common.RawBytes{0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0}
		original := createUDP()

		fromRaw, err := UDPFromRaw(raw)
		SoMsg("Must build from raw without error", err, ShouldBeNil)
		SoMsg("Wrongly rebuilt from raw", fromRaw, ShouldResemble, &original)
	})
}

func TestUDPValidate(t *testing.T) {
	Convey("It is structure of size 10, must be ok", t, func() {
		u := createUDP()

		So(u.TotalLen, ShouldEqual, 10)
		err := u.Validate(int(u.TotalLen) - UDPLen)
		SoMsg("This structure must be seen as valid", err, ShouldBeNil)
	})
}

func TestUDPParse(t *testing.T) {
	Convey("Must parse into the same representation", t, func() {
		// assuming we have tested UDPPack
		u := createUDP()
		raw, err := u.Pack(true)
		u2 := UDP{0, 0, 0xA,
			make(common.RawBytes, 2)}

		u2.Parse(raw)
		SoMsg("Must parse this valid input", err, ShouldBeNil)
		SoMsg("Parsed content must match expected", u2, ShouldResemble, u)
	})
}

func TestUDPPack(t *testing.T) {
	Convey("Binary content must match", t, func() {
		u := createUDP()
		raw, err := u.Pack(true)

		SoMsg("Must pack without error", err, ShouldBeNil)
		SoMsg("Packed content must match expected", raw, ShouldResemble,
			common.RawBytes{0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0})
	})
}

func TestUDPWrite(t *testing.T) {
	Convey("Binary content must match", t, func() {
		u := createUDP()
		raw := make(common.RawBytes, 8)
		err := u.Write(raw)

		SoMsg("Must write without error", err, ShouldBeNil)
		SoMsg("Wrong content written", raw,
			ShouldResemble, common.RawBytes{0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0})
	})
}
