// Copyright 2020 Anapaya Systems
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

package segfetcher_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/segment/segfetcher"
)

func TestRevocationsString(t *testing.T) {
	testCases := map[string]struct {
		Input  map[snet.PathInterface]struct{}
		Output string
	}{
		"nil": {
			Input:  nil,
			Output: "[]",
		},
		"empty": {
			Input:  make(map[snet.PathInterface]struct{}),
			Output: "[]",
		},
		"one element": {
			Input: map[snet.PathInterface]struct{}{
				{IA: addr.MustParseIA("1-ff00:0:1"), ID: 1}: {},
			},
			Output: "[1-ff00:0:1#1]",
		},
		"two elements": {
			Input: map[snet.PathInterface]struct{}{
				{IA: addr.MustParseIA("1-ff00:0:1"), ID: 1}: {},
				{IA: addr.MustParseIA("1-ff00:0:2"), ID: 2}: {},
			},
			Output: "[1-ff00:0:1#1 1-ff00:0:2#2]",
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.Output, segfetcher.RevocationsString(tc.Input))
		})
	}
}
