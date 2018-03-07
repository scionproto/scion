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
		{"1ns", 1 * time.Nanosecond, true},
		{"1us", 1 * time.Microsecond, true},
		{"1µs", 1 * time.Microsecond, true},
		{"1ms", 1 * time.Millisecond, true},
		{"1s", 1 * time.Second, true},
		{"1m", 1 * time.Minute, true},
		{"1h", 1 * time.Hour, true},
		{"1d", 24 * time.Hour, true},
		{"1w", 7 * 24 * time.Hour, true},
		{"1y", 365 * 24 * time.Hour, true},
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
