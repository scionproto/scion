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

func Test_ISDFromString(t *testing.T) {
	var testCases = []struct {
		src string
		isd ISD
		ok  bool
	}{
		{"", 0, false},
		{"a", 0, false},
		{"0", 0, true},
		{"1", 1, true},
		{"65535", MaxISD, true},
		{"65536", 0, false},
	}
	Convey("ISDFromString should parse strings correctly", t, func() {
		for _, tc := range testCases {
			Convey(tc.src, func() {
				isd, err := ISDFromString(tc.src)
				if !tc.ok {
					SoMsg("Must raise parse error", err, ShouldNotBeNil)
					return
				}
				SoMsg("Must parse cleanly", err, ShouldBeNil)
				SoMsg("Parsed ISD must be correct", isd, ShouldEqual, tc.isd)
			})
		}
	})
}

func Test_ISDFromFileFmt(t *testing.T) {
	var testCases = []struct {
		src string
		isd ISD
		ok  bool
	}{
		{"", 0, false},
		{"ISD", 0, false},
		{"ISD0", 0, true},
		{"ISD65535", MaxISD, true},
	}
	Convey("ISDFromFileFmt should parse strings correctly", t, func() {
		for _, tc := range testCases {
			Convey(tc.src, func() {
				isd, err := ISDFromFileFmt(tc.src, true)
				if !tc.ok {
					SoMsg("Must raise parse error", err, ShouldNotBeNil)
					return
				}
				SoMsg("Must parse cleanly", err, ShouldBeNil)
				SoMsg("Parsed ISD must be correct", isd, ShouldEqual, tc.isd)
			})
		}
	})
}

func Test_ASFromString(t *testing.T) {
	var testCases = []struct {
		src string
		as  AS
		ok  bool
	}{
		// BGP AS parsing.
		{"", 0, false},
		{"0", 0, true},
		{"0x0", 0, false},
		{"ff", 0, false},
		{"1", 1, true},
		{"4294967295", MaxBGPAS, true},
		{"4294967296", 0, false},
		// SCION AS parsing.
		{":", 0, false},
		{"0:0:0", 0, true},
		{"0:0:0:", 0, false},
		{":0:0:", 0, false},
		{"0:0", 0, false},
		{"0:0:1", 1, true},
		{"1:0:0", 0x000100000000, true},
		{"ffff:ffff:ffff", MaxAS, true},
		{"10000:0:0", 0, false},
		{"0:10000:0", 0, false},
		{"0:0:10000", 0, false},
		{"0:0x0:0", 0, false},
	}
	Convey("ASFromString should parse strings correctly", t, func() {
		for _, tc := range testCases {
			Convey(tc.src, func() {
				as, err := ASFromString(tc.src)
				if !tc.ok {
					SoMsg("Must raise parse error", err, ShouldNotBeNil)
					return
				}
				SoMsg("Must parse cleanly", err, ShouldBeNil)
				SoMsg("Parsed AS must be correct", as, ShouldEqual, tc.as)
			})
		}
	})
}

func Test_ASFromFileFmt(t *testing.T) {
	// Only test the differences from ASFromString.
	var testCases = []struct {
		src string
		as  AS
	}{
		// BGP AS parsing.
		{"0", 0},
		{"4294967295", MaxBGPAS},
		// SCION AS parsing.
		{"0_0_0", 0},
		{"0_0_1", 1},
		{"1_0_0", 0x000100000000},
		{"ffff_ffff_ffff", MaxAS},
	}
	Convey("ASFromFileFmt should parse file-formatted strings correctly", t, func() {
		for _, tc := range testCases {
			src := tc.src
			Convey(src, func() {
				as, err := ASFromFileFmt(src, false)
				SoMsg("Must parse cleanly", err, ShouldBeNil)
				SoMsg("Parsed AS must be correct", as, ShouldEqual, tc.as)
			})
			src = ASFmtPrefix + src
			Convey(src, func() {
				as, err := ASFromFileFmt(src, true)
				SoMsg("Must parse cleanly", err, ShouldBeNil)
				SoMsg("Parsed AS must be correct", as, ShouldEqual, tc.as)
			})
		}
	})
}

func Test_AS_String(t *testing.T) {
	var testCases = []struct {
		as  AS
		out string
	}{
		{0, "0"},
		{1, "1"},
		{999, "999"},
		{MaxBGPAS, "4294967295"},
		{MaxBGPAS + 1, "1:0:0"},
		{0x0001fcd10001, "1:fcd1:1"},
		{MaxAS, "ffff:ffff:ffff"},
		{MaxAS + 1, "281474976710656 [Illegal AS: larger than 281474976710655]"},
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

func Test_AS_FileFmt(t *testing.T) {
	// Only test differences from AS.String()
	var testCases = []struct {
		as  AS
		out string
	}{
		{0, "0"},
		{MaxBGPAS, "4294967295"},
		{MaxBGPAS + 1, "1_0_0"},
		{0x0001fcd10001, "1_fcd1_1"},
		{MaxAS, "ffff_ffff_ffff"},
	}
	Convey("AS.FileFmt() should format correctly", t, func() {
		for _, tc := range testCases {
			Convey(tc.out, func() {
				s := tc.as.FileFmt()
				SoMsg("Format must match", s, ShouldEqual, tc.out)
			})
		}
	})
}

func Test_IAFromRaw(t *testing.T) {
	Convey("IAFromRaw should parse bytes correctly", t, func() {
		nia := IAFromRaw(rawIA)
		So(nia.I, ShouldEqual, ia.I)
		So(nia.A, ShouldEqual, ia.A)
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
		{"1-4294967295", &IA{1, MaxBGPAS}},
		{"1-4294967296", nil},
		{"1-1:0:0", &IA{1, 0x000100000000}},
		{"1-1:fcd1:1", &IA{1, 0x0001fcd10001}},
		{"1-ffff:ffff:10000", nil},
		{"65535-ffff:ffff:ffff", &IA{MaxISD, MaxAS}},
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

func Test_IAFromFileFmt(t *testing.T) {
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
		{"1-4294967295", &IA{1, MaxBGPAS}},
		{"1-4294967296", nil},
		{"1-1:0:0", &IA{1, 0x000100000000}},
		{"1-1:fcd1:1", &IA{1, 0x0001fcd10001}},
		{"1-ffff:ffff:10000", nil},
		{"65535-ffff:ffff:ffff", &IA{MaxISD, MaxAS}},
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
		{IA{1, MaxBGPAS}, "1-4294967295"},
		{IA{1, MaxBGPAS + 1}, "1-1:0:0"},
		{IA{65535, MaxAS}, "65535-ffff:ffff:ffff"},
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
