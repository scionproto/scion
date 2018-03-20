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

package addr

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	rawIA = []byte{0xF0, 0x11, 0xF2, 0x33, 0x44, 0x55, 0x66, 0x77}
	ia    = IA{I: 0xF011, A: 0xF23344556677}
)

func Test_AS_String(t *testing.T) {
	var testCases = []struct {
		as  AS
		out string
	}{
		{0, "0"},
		{1, "1"},
		{999, "999"},
		{1000, "1_000"},
		{11000, "11_000"},
		{999999, "999_999"},
		{1000000, "1_000_000"},
		{999999999, "999_999_999"},
		{1000000000, "1_000_000_000"},
		{999999999999, "999_999_999_999"},
		{1000000000000, "1_000_000_000_000"},
		{281474976710655, "281_474_976_710_655"},
		{281474976710656, "281474976710656 [Illegal AS: larger than 281474976710655]"},
	}
	Convey("AS.String() should format correctly", t, func() {
		for _, tc := range testCases {
			Convey(tc.out, func() {
				s := tc.as.String()
				SoMsg("Format must match", s, ShouldEqual, tc.out)
			})
		}
	})
}

func Test_IAFromRaw(t *testing.T) {
	Convey("IAFromRaw should parse bytes correctly", t, func() {
		ia := IAFromRaw(rawIA)
		So(ia.I, ShouldEqual, ia.I)
		So(ia.A, ShouldEqual, ia.A)
	})
}

func Test_IAFromString(t *testing.T) {
	var testCases = []struct {
		src string
		ia  *IA
	}{
		{"", nil},
		{"a", nil},
		{"1a-2b", nil},
		{"-", nil},
		{"1-", nil},
		{"-1", nil},
		{"-1-", nil},
		{"1--1", nil},
		{"0-0", &IA{0, 0}},
		{"1-1", &IA{1, 1}},
		{"65535-1", &IA{MaxISD, 1}},
		{"65536-1", nil},
		{"1-281474976710655", &IA{1, MaxAS}},
		{"1-281474976710656", nil},
		{"65535-281474976710655", &IA{MaxISD, MaxAS}},
		{"1-_", nil},
		{"1-_0", nil},
		{"1-_00", nil},
		{"1-_000", nil},
		{"1-_0000", nil},
		{"1-1_0", nil},
		{"1-1_00", nil},
		{"1-1_000", &IA{1, 1000}},
		{"1-1_0000", nil},
		{"1-11_000", &IA{1, 11000}},
		{"1-111_000", &IA{1, 111000}},
		{"1-1111_000", nil},
		{"65535-281_474_976_710_655", &IA{MaxISD, MaxAS}},
		{"65535-281_474_976_710_656", nil},
		{"65535-281_474_976_7106_55", nil},
		{"65535-281_474_976_71_0655", nil},
		{"65535-1281_474_976_710", nil},
	}
	Convey("IAFromString should parse strings correctly", t, func() {
		for _, tc := range testCases {
			Convey(tc.src, func() {
				ia, err := IAFromString(tc.src)
				if tc.ia == nil {
					SoMsg("Must raise parse error", err, ShouldNotBeNil)
					return
				}
				SoMsg("Must parse cleanly", err, ShouldBeNil)
				SoMsg("Parsed IA must be correct", ia, ShouldResemble, *tc.ia)
			})
		}

	})
}

func Test_IA_Write(t *testing.T) {
	Convey("ISD_AS.Write() should output bytes correctly", t, func() {
		output := make([]byte, IABytes)
		ia.Write(output)
		So(output, ShouldResemble, rawIA)
	})
}

func Test_IA_String(t *testing.T) {
	var testCases = []struct {
		ia  IA
		out string
	}{
		{IA{0, 0}, "0-0"},
		{IA{1, 1}, "1-1"},
		{IA{65535, 1}, "65535-1"},
		{IA{65535, 281474976710655}, "65535-281_474_976_710_655"},
		{IA{1, 281474976710656}, "1-281474976710656 [Illegal AS: larger than 281474976710655]"},
	}
	Convey("IA.String() should format correctly", t, func() {
		for _, tc := range testCases {
			Convey(tc.out, func() {
				s := tc.ia.String()
				SoMsg("Format must match", s, ShouldEqual, tc.out)
			})
		}
	})
}
