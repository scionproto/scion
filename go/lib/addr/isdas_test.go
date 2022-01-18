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

func TestParseISD(t *testing.T) {
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
	for _, tc := range testCases {
		t.Run(tc.src, func(t *testing.T) {
			isd, err := ParseISD(tc.src)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.isd, isd, "Parsed ISD must be correct")
		})
	}
}

func TestParseAS(t *testing.T) {
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
	for _, tc := range testCases {
		t.Run(tc.src, func(t *testing.T) {
			as, err := ParseAS(tc.src)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, err, "Must parse cleanly")
			assert.Equal(t, tc.as, as, "Parsed AS must be correct")
		})
	}
}

func TestParseIA(t *testing.T) {
	ref := func(isd ISD, as AS) *IA {
		ia := MustIAFrom(isd, as)
		return &ia
	}
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
		{"0-0", ref(0, 0)},
		{"1-1", ref(1, 1)},
		{"65535-1", ref(MaxISD, 1)},
		{"65536-1", nil},
		{"1-4294967295", ref(1, MaxBGPAS)},
		{"1-4294967296", nil},
		{"1-1:0:0", ref(1, 0x000100000000)},
		{"1-1:fcd1:1", ref(1, 0x0001fcd10001)},
		{"1-ffff:ffff:10000", nil},
		{"65535-ffff:ffff:ffff", ref(MaxISD, MaxAS)},
	}
	for _, tc := range testCases {
		t.Run(tc.src, func(t *testing.T) {
			ia, err := ParseIA(tc.src)
			if tc.ia == nil {
				assert.Error(t, err, "Must raise parse error", err)
				return
			}
			assert.NoError(t, err, "Must parse cleanly", err)
			assert.Equal(t, *tc.ia, ia, "Parsed IA must be correct")
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

func TestIAString(t *testing.T) {
	var testCases = []struct {
		ia  IA
		out string
	}{
		{MustIAFrom(0, 0), "0-0"},
		{MustIAFrom(1, 1), "1-1"},
		{MustIAFrom(65535, 1), "65535-1"},
		{MustIAFrom(1, MaxBGPAS), "1-4294967295"},
		{MustIAFrom(1, MaxBGPAS+1), "1-1:0:0"},
		{MustIAFrom(65535, MaxAS), "65535-ffff:ffff:ffff"},
	}
	t.Log("IA.String() should format correctly")
	for _, tc := range testCases {
		t.Run(tc.out, func(t *testing.T) {
			s := tc.ia.String()
			assert.Equal(t, tc.out, s, "Format must match")
		})
	}
}

func TestParseFormattedISD(t *testing.T) {
	var testCases = map[string]struct {
		value        string
		expected     ISD
		options      []FormatOption
		errAssertion assert.ErrorAssertionFunc
	}{
		"empty": {
			value:        "",
			expected:     0,
			errAssertion: assert.Error,
		},
		"prefix only": {
			value:        "ISD",
			expected:     0,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.Error,
		},
		"zero ISD, unexpected prefix": {
			value:        "ISD0",
			expected:     0,
			errAssertion: assert.Error,
		},
		"valid ISD, unexpected prefix": {
			value:        "ISD65535",
			expected:     MaxISD,
			errAssertion: assert.Error,
		},
		"zero ISD, expect prefix": {
			value:        "0",
			expected:     0,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.Error,
		},
		"valid ISD, expect prefix": {
			value:        "65535",
			expected:     MaxISD,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.Error,
		},
		"zero ISD, prefix": {
			value:        "ISD0",
			expected:     0,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.NoError,
		},
		"valid ISD, prefix": {
			value:        "ISD65535",
			expected:     MaxISD,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.NoError,
		},
		"zero ISD": {
			value:        "0",
			expected:     0,
			errAssertion: assert.NoError,
		},
		"valid ISD": {
			value:        "65535",
			expected:     MaxISD,
			errAssertion: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			isd, err := ParseFormattedISD(tc.value, tc.options...)
			tc.errAssertion(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, err, "Must parse cleanly")
			assert.Equal(t, tc.expected, isd, "Parsed ISD must be correct")
		})
	}
}

func TestParseFormattedAS(t *testing.T) {
	var testCases = map[string]struct {
		value        string
		expected     AS
		options      []FormatOption
		errAssertion assert.ErrorAssertionFunc
	}{
		"empty": {
			value:        "",
			expected:     0,
			errAssertion: assert.Error,
		},
		"prefix only": {
			value:        "AS",
			expected:     0,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.Error,
		},
		"bgp, unexpected prefix": {
			value:        "AS4294967295",
			expected:     MaxBGPAS,
			errAssertion: assert.Error,
		},
		"bgp, expect prefix": {
			value:        "0",
			expected:     0,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.Error,
		},
		"0_0_0, wrong separator": {
			value:        "0_0_0",
			expected:     0,
			options:      []FormatOption{WithSeparator("~")},
			errAssertion: assert.Error,
		},
		"bgp 0, prefix": {
			value:        "AS0",
			expected:     0,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.NoError,
		},
		"bgp max, prefix": {
			value:        "AS4294967295",
			expected:     MaxBGPAS,
			options:      []FormatOption{WithDefaultPrefix()},
			errAssertion: assert.NoError,
		},
		"bgp 0": {
			value:        "0",
			expected:     0,
			errAssertion: assert.NoError,
		},
		"bgp max": {
			value:        "4294967295",
			expected:     MaxBGPAS,
			errAssertion: assert.NoError,
		},
		"0_0_0": {
			value:        "0_0_0",
			expected:     0,
			options:      []FormatOption{WithFileSeparator()},
			errAssertion: assert.NoError,
		},
		"0_0_1": {
			value:        "0_0_1",
			expected:     1,
			options:      []FormatOption{WithFileSeparator()},
			errAssertion: assert.NoError,
		},
		"1_0_0": {
			value:        "1_0_0",
			expected:     0x000100000000,
			options:      []FormatOption{WithFileSeparator()},
			errAssertion: assert.NoError,
		},
		"ffff_ffff_ffff": {
			value:        "ffff_ffff_ffff",
			expected:     MaxAS,
			options:      []FormatOption{WithFileSeparator()},
			errAssertion: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			as, err := ParseFormattedAS(tc.value, tc.options...)
			tc.errAssertion(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tc.expected, as)
		})
	}
}

func TestASFileFmt(t *testing.T) {
	var testCases = map[string]struct {
		value    AS
		options  []FormatOption
		expected string
	}{
		"bgp 0": {
			value:    0,
			expected: "0",
		},
		"bgp max": {
			value:    MaxBGPAS,
			expected: "4294967295",
		},
		"1:0:0": {
			value:    MaxBGPAS + 1,
			expected: "1:0:0",
		},
		"1:0:0, file": {
			value:    MaxBGPAS + 1,
			options:  []FormatOption{WithFileSeparator()},
			expected: "1_0_0",
		},
		"1:0:0, ~": {
			value:    MaxBGPAS + 1,
			options:  []FormatOption{WithSeparator("~")},
			expected: "1~0~0",
		},
		"1:fcd1:1": {
			value:    0x0001fcd10001,
			options:  []FormatOption{WithFileSeparator()},
			expected: "1_fcd1_1",
		},
		"max": {
			value:    MaxAS,
			options:  []FormatOption{WithFileSeparator()},
			expected: "ffff_ffff_ffff",
		},
		"prefix": {
			value:    MaxAS,
			options:  []FormatOption{WithFileSeparator(), WithDefaultPrefix()},
			expected: "ASffff_ffff_ffff",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expected, FormatAS(tc.value, tc.options...))
		})
	}
}
