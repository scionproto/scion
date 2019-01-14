// Copyright 2019 ETH Zurich
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

package pathpol

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSequenceLoadFromString(t *testing.T) {
	testCases := []struct {
		Name     string
		String   string
		Sequence Sequence
		Valid    bool
	}{
		{
			Name:     "Empty sequence",
			String:   "",
			Sequence: newSequence(t, []string{""}),
			Valid:    true,
		},
		{
			Name:     "Empty sequence second",
			String:   "",
			Sequence: newSequence(t, []string{}),
			Valid:    true,
		},
		{
			Name:     "Single ISD",
			String:   "0",
			Sequence: newSequence(t, []string{"0"}),
			Valid:    true,
		},
		{
			Name:     "Full Predicate",
			String:   "1-2#3,2",
			Sequence: newSequence(t, []string{"1-2#3,2"}),
			Valid:    true,
		},
		{
			Name:     "Two predicates",
			String:   "1-2 1-4#0",
			Sequence: newSequence(t, []string{"1-2", "1-4#0"}),
			Valid:    true,
		},
		{
			Name:   "Bad predicates",
			String: "1-2 1-4#1,2,0",
			Valid:  false,
		},
	}

	Convey("TestSequenceLoadFromString", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				var sequence Sequence
				err := sequence.LoadFromString(tc.String)
				if tc.Valid {
					SoMsg("err", err, ShouldBeNil)
					SoMsg("sequence", sequence, ShouldResemble, tc.Sequence)
				} else {
					SoMsg("err", err, ShouldNotBeNil)
				}
			})
		}
	})
}

func TestSequenceString(t *testing.T) {
	Convey("TestSequenceString", t, func() {
		sequenceStr := "0-0#0 1-2#0 1-2#3 0-0#0"
		sequence, err := NewSequence([]string{"0", "1-2", "1-2#3", "0"})
		SoMsg("err", err, ShouldBeNil)
		SoMsg("sequence", sequenceStr, ShouldResemble, sequence.String())
	})
}
