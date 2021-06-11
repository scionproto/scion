// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package util_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/util"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input          string
		output         time.Duration
		errorAssertion assert.ErrorAssertionFunc
	}{
		{"", 0, assert.Error},      // Empty string
		{"0", 0, assert.Error},     // No unit provided
		{"1d12h", 0, assert.Error}, // Multiple units
		{"2ns", 2 * time.Nanosecond, assert.NoError},
		{"33us", 33 * time.Microsecond, assert.NoError},
		{"4444µs", 4444 * time.Microsecond, assert.NoError},
		{"55555ms", 55555 * time.Millisecond, assert.NoError},
		{"101s", 101 * time.Second, assert.NoError},
		{"102m", 102 * time.Minute, assert.NoError},
		{"103h", 103 * time.Hour, assert.NoError},
		{"104d", 104 * 24 * time.Hour, assert.NoError},
		{"105w", 105 * 7 * 24 * time.Hour, assert.NoError},
		{"106y", 106 * 365 * 24 * time.Hour, assert.NoError},
		{"-1h", -1 * time.Hour, assert.NoError},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("Input: %q", test.input), func(t *testing.T) {
			ret, err := util.ParseDuration(test.input)
			test.errorAssertion(t, err)
			assert.Equal(t, test.output, ret)
		})
	}
}

func TestFmtDuration(t *testing.T) {
	tests := []struct {
		input  time.Duration
		output string
	}{
		{0 * time.Nanosecond, "0s"},
		{2 * time.Nanosecond, "2ns"},
		{33 * time.Microsecond, "33us"},
		{44 * time.Millisecond, "44ms"},
		{55 * time.Second, "55s"},
		{66 * time.Hour, "66h"},
		{48 * time.Hour, "2d"},
		{30 * util.Day, "30d"},
		{35 * util.Day, "5w"},
		{101 * util.Year, "101y"},
		{-101 * util.Year, "-101y"},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("Input: %v", test.output), func(t *testing.T) {
			ret := util.FmtDuration(test.input)
			assert.Equal(t, test.output, ret)
		})
	}
}
