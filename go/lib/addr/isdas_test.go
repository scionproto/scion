// Copyright 2016 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

	"github.com/stretchr/testify/assert"
)

var (
	rawIA = []byte{0xF0, 0x11, 0xF2, 0x33, 0x44, 0x55, 0x66, 0x77}
	ia    = IA{I: 0xF011, A: 0xF23344556677}
)

func TestISDFromString(t *testing.T) {
	var testCases = []struct {
		src       string
		isd       ISD
		assertErr assert.ErrorAssertionFunc
	}{
		{"", 0, assert.Error},
		{"a", 0, assert.Error},
		{"0", 0, assert.NoError},
		{"1", 1, assert.NoError},
		{"65535", MaxISD, assert.NoError},
		{"65536", 0, assert.Error},
	}
	t.Log("ISDFromString should parse strings correctly")
	for _, tc := range testCases {
		t.Run(tc.src, func(t *testing.T) {
			isd, err := ISDFromString(tc.src)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.isd, isd, "Parsed ISD must be correct")
		})
	}
}

func TestISDFromFileFmt(t *testing.T) {
	var testCases = []struct {
		src       string
		isd       ISD
		assertErr assert.ErrorAssertionFunc
	}{
		{"", 0, assert.Error},
		{"ISD", 0, assert.Error},
		{"ISD0", 0, assert.NoError},
		{"ISD65535", MaxISD, assert.NoError},
	}
	t.Log("ISDFromFileFmt should parse strings correctly")
	for _, tc := range testCases {
		t.Run(tc.src, func(t *testing.T) {
			isd, err := ISDFromFileFmt(tc.src, true)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, err, "Must parse cleanly")
			assert.Equal(t, tc.isd, isd, "Parsed ISD must be correct")
		})
	}
}

func TestASFromString(t *testing.T) {
	var testCases = []struct {
		src       string
		as        AS
		assertErr assert.ErrorAssertionFunc
	}{
		// BGP AS parsing.
		{"", 0, assert.Error},
		{"0", 0, assert.NoError},
		{"0x0", 0, assert.Error},
		{"ff", 0, assert.Error},
		{"1", 1, assert.NoError},
		{"4294967295", MaxBGPAS, assert.NoError},
		{"4294967296", 0, assert.Error},
		// SCION AS parsing.
		{":", 0, assert.Error},
		{"0:0:0", 0, assert.NoError},
		{"0:0:0:", 0, assert.Error},
		{":0:0:", 0, assert.Error},
		{"0:0", 0, assert.Error},
		{"0:0:1", 1, assert.NoError},
		{"1:0:0", 0x000100000000, assert.NoError},
		{"ffff:ffff:ffff", MaxAS, assert.NoError},
		{"10000:0:0", 0, assert.Error},
		{"0:10000:0", 0, assert.Error},
		{"0:0:10000", 0, assert.Error},
		{"0:0x0:0", 0, assert.Error},
	}
	t.Log("ASFromString should parse strings correctly")
	for _, tc := range testCases {
		t.Run(tc.src, func(t *testing.T) {
			as, err := ASFromString(tc.src)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, err, "Must parse cleanly")
			assert.Equal(t, tc.as, as, "Parsed AS must be correct")
		})
	}
}

func TestASFromFileFmt(t *testing.T) {
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
	t.Log("ASFromFileFmt should parse file-formatted strings correctly")
	for _, tc := range testCases {
		src := tc.src
		t.Run(src, func(t *testing.T) {
			as, err := ASFromFileFmt(src, false)
			assert.NoError(t, err, "Must parse cleanly")
			assert.Equal(t, tc.as, as, "Parsed AS must be correct")
			src = ASFmtPrefix + src
			as, err = ASFromFileFmt(src, true)
			assert.NoError(t, err, "Must parse cleanly")
			assert.Equal(t, tc.as, as, "Parsed AS must be correct")
		})
	}
}

func TestASString(t *testing.T) {
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
	t.Log("AS.String() should format correctly")
	for _, tc := range testCases {
		t.Run(tc.out, func(t *testing.T) {
			s := tc.as.String()
			assert.Equal(t, tc.out, s, "Format must match")
		})
	}
}

func TestASFileFmt(t *testing.T) {
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
	t.Log("AS.FileFmt() should format correctly")
	for _, tc := range testCases {
		t.Run(tc.out, func(t *testing.T) {
			s := tc.as.FileFmt()
			assert.Equal(t, tc.out, s, "Format must match")
		})
	}
}

func TestIAFromRaw(t *testing.T) {
	t.Log("IAFromRaw should parse bytes correctly")
	nia := IAFromRaw(rawIA)
	assert.Equal(t, ia.I, nia.I)
	assert.Equal(t, ia.A, nia.A)
}

func TestIAFromString(t *testing.T) {
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
	t.Log("IAFromString should parse strings correctly")
	for _, tc := range testCases {
		t.Run(tc.src, func(t *testing.T) {
			ia, err := IAFromString(tc.src)
			if tc.ia == nil {
				assert.Error(t, err, "Must raise parse error", err)
				return
			}
			assert.NoError(t, err, "Must parse cleanly", err)
			assert.Equal(t, *tc.ia, ia, "Parsed IA must be correct")
		})
	}

}

func TestIAFromFileFmt(t *testing.T) {
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
	t.Log("IAFromString should parse strings correctly")
	for _, tc := range testCases {
		t.Run(tc.src, func(t *testing.T) {
			ia, err := IAFromString(tc.src)
			if tc.ia == nil {
				assert.Error(t, err, "Must raise parse error", err)
				return
			}

			assert.NoError(t, err, "Must parse cleanly", err)
			assert.Equal(t, *tc.ia, ia, "Parsed IA must be correct")
		})
	}

}

func TestIAWrite(t *testing.T) {
	t.Log("ISD_AS.Write() should output bytes correctly")
	output := make([]byte, IABytes)
	ia.Write(output)
	assert.Equal(t, rawIA, output)
}

func TestIAString(t *testing.T) {
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
	t.Log("IA.String() should format correctly")
	for _, tc := range testCases {
		t.Run(tc.out, func(t *testing.T) {
			s := tc.ia.String()
			assert.Equal(t, tc.out, s, "Format must match")
		})
	}
}
