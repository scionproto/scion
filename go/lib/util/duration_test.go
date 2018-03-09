// Copyright 2018 ETH Zurich
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

package util

import (
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_ParseDuration(t *testing.T) {
	tests := []struct {
		input  string
		output time.Duration
		isOk   bool
	}{
		{"", 0, false},      // Empty string
		{"0", 0, false},     // No unit provided
		{"1d12h", 0, false}, // Multiple units
		{"2ns", 2 * time.Nanosecond, true},
		{"33us", 33 * time.Microsecond, true},
		{"4444µs", 4444 * time.Microsecond, true},
		{"55555ms", 55555 * time.Millisecond, true},
		{"101s", 101 * time.Second, true},
		{"102m", 102 * time.Minute, true},
		{"103h", 103 * time.Hour, true},
		{"104d", 104 * 24 * time.Hour, true},
		{"105w", 105 * 7 * 24 * time.Hour, true},
		{"106y", 106 * 365 * 24 * time.Hour, true},
	}
	Convey("Test ParseDuration", t, func() {
		for _, test := range tests {
			Convey(fmt.Sprintf("Input: %q", test.input), func() {
				ret, err := ParseDuration(test.input)
				if test.isOk {
					SoMsg("No error", err, ShouldBeNil)
					SoMsg("Result should be correct", ret, ShouldEqual, test.output)
				} else {
					SoMsg("Error", err, ShouldNotBeNil)
				}
			})
		}
	})
}

func Test_FmtDuration(t *testing.T) {
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
		{30 * day, "30d"},
		{35 * day, "5w"},
		{101 * year, "101y"},
	}
	Convey("Test FmtDuration", t, func() {
		for _, test := range tests {
			Convey(fmt.Sprintf("Input: %v", test.output), func() {
				ret := FmtDuration(test.input)
				SoMsg("Result should be correct", ret, ShouldEqual, test.output)
			})
		}
	})

}
