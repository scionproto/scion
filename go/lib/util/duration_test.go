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

func Test_WriteDuration(t *testing.T) {
	tests := []struct {
		input  time.Duration
		output string
		isOk   bool
	}{
		{2 * time.Nanosecond, "2ns", true},
		{33 * time.Microsecond, "33us", true},
		{44 * time.Millisecond, "44ms", true},
		{55 * time.Second, "55s", true},
		{66 * time.Hour, "66h", true},
		{48 * time.Hour, "48h", false},
		{48 * time.Hour, "2d", true},
		{30 * day, "30d", true},
		{35 * day, "35d", false},
		{35 * day, "5w", true},
		{101 * year, "101y", true},
	}
	Convey("Test WriteDuration", t, func() {
		for _, test := range tests {
			Convey(fmt.Sprintf("Input: %v", test.output), func() {
				ret := WriteDuration(test.input)
				if test.isOk {
					SoMsg("Result should be correct", ret, ShouldEqual, test.output)
				} else {
					SoMsg("Result should not match", ret, ShouldNotEqual, test.output)
				}
			})
		}
	})

}
