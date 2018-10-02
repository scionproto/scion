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

package sciond

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNewPathInterface(t *testing.T) {
	testCases := []struct {
		Name  string
		In    string
		PI    PathInterface
		Valid bool
	}{
		{
			Name:  "ISD wildcard",
			In:    "0",
			PI:    mustPathInterface(t, "0-0#0"),
			Valid: true,
		},
		{
			Name:  "AS, IF wildcard omitted",
			In:    "1",
			PI:    mustPathInterface(t, "1-0#0"),
			Valid: true,
		},
		{
			Name:  "IF wildcard omitted",
			In:    "1-0",
			PI:    mustPathInterface(t, "1-0#0"),
			Valid: true,
		},
		{
			Name:  "basic wildcard",
			In:    "1-0#0",
			PI:    mustPathInterface(t, "1-0#0"),
			Valid: true,
		},
		{
			Name:  "AS wildcard, interface set",
			In:    "1-0#1",
			Valid: false,
		},
		{
			Name:  "ISD wildcard, AS set",
			In:    "0-1#0",
			PI:    mustPathInterface(t, "0-1#0"),
			Valid: true,
		},
		{
			Name:  "ISD wildcard, AS set, interface set",
			In:    "0-1#1",
			PI:    mustPathInterface(t, "0-1#1"),
			Valid: true,
		},
		{
			Name:  "ISD wildcard, AS set and interface omitted",
			In:    "0-1",
			PI:    mustPathInterface(t, "0-1#0"),
			Valid: true,
		},
		{
			Name:  "IF wildcard omitted, AS set",
			In:    "1-1",
			PI:    mustPathInterface(t, "1-1#0"),
			Valid: true,
		},
		{
			Name:  "bad -",
			In:    "1-1-0",
			Valid: false,
		},
		{
			Name:  "bad #",
			In:    "1-1#0#",
			Valid: false,
		},
		{
			Name:  "bad IF",
			In:    "1-1#e",
			Valid: false,
		},
		{
			Name:  "bad AS",
			In:    "1-12323433243534#0",
			Valid: false,
		},
		{
			Name:  "bad ISD",
			In:    "1123212-23#0",
			Valid: false,
		},
	}

	Convey("TestNewPathInterface", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				pi, err := NewPathInterface(tc.In)
				if tc.Valid {
					SoMsg("err", err, ShouldBeNil)
					SoMsg("pi", pi, ShouldResemble, tc.PI)
				} else {
					SoMsg("err", err, ShouldNotBeNil)
				}
			})
		}
	})
}

func mustPathInterface(t *testing.T, str string) PathInterface {
	t.Helper()

	pi, err := NewPathInterface(str)
	xtest.FailOnErr(t, err)
	return pi
}
