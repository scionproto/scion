// Copyright 2021 Anapaya Systems
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

package matchers_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/private/xtest/matchers"
)

type testPartial struct {
	A int
	B string
	C []byte
}

type testPartial2 struct {
	A int
	B string
	C []byte
}

func TestPartialStructMatches(t *testing.T) {
	testCases := map[string]struct {
		Matcher     gomock.Matcher
		Input       any
		ExpectMatch bool
	}{
		"exact match": {
			Matcher: matchers.PartialStruct{
				Target: testPartial{
					A: 1,
					B: "1",
					C: []byte("1"),
				},
			},
			Input: testPartial{
				A: 1,
				B: "1",
				C: []byte("1"),
			},
			ExpectMatch: true,
		},
		"exact ptr": {
			Matcher: matchers.PartialStruct{
				Target: &testPartial{
					A: 1,
					B: "1",
					C: []byte("1"),
				},
			},
			Input: &testPartial{
				A: 1,
				B: "1",
				C: []byte("1"),
			},
			ExpectMatch: true,
		},
		"partial": {
			Matcher: matchers.PartialStruct{
				Target: testPartial{
					A: 1,
				},
			},
			Input: testPartial{
				A: 1,
				B: "2",
				C: []byte("2"),
			},
			ExpectMatch: true,
		},
		"ptr non-ptr mix": {
			Matcher: matchers.PartialStruct{
				Target: &testPartial{
					A: 1,
				},
			},
			Input: testPartial{
				A: 1,
			},
			ExpectMatch: false,
		},
		"different type": {
			Matcher: matchers.PartialStruct{
				Target: testPartial{
					A: 1,
				},
			},
			Input: testPartial2{
				A: 1,
			},
			ExpectMatch: false,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			am := tc.Matcher.Matches(tc.Input)
			assert.Equal(t, tc.ExpectMatch, am, tc.Matcher.String())
		})
	}
}
