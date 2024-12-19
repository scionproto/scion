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

package routing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/gateway/routing"
	"github.com/scionproto/scion/pkg/addr"
)

func TestSingleIAMatcher(t *testing.T) {
	testCases := map[string]struct {
		Matcher    routing.IAMatcher
		Matches    []string
		NotMatches []string
	}{
		"match": {
			Matcher:    routing.NewIAMatcher(t, "1-ff00:0:110"),
			Matches:    []string{"1-ff00:0:110"},
			NotMatches: []string{"1-ff00:0:111", "2-ff00:0:110"},
		},
		"match wildcard": {
			Matcher: routing.NewIAMatcher(t, "0-0"),
			Matches: []string{"1-ff00:0:110"},
		},
		"match wildcard ISD": {
			Matcher:    routing.NewIAMatcher(t, "0-ff00:0:110"),
			Matches:    []string{"1-ff00:0:110", "2-ff00:0:110"},
			NotMatches: []string{"1-ff00:0:111"},
		},
		"match wildcard AS": {
			Matcher:    routing.NewIAMatcher(t, "1-0"),
			Matches:    []string{"1-ff00:0:110", "1-ff00:0:110"},
			NotMatches: []string{"2-ff00:0:110"},
		},
		"negated match": {
			Matcher:    routing.NewIAMatcher(t, "!1-ff00:0:110"),
			Matches:    []string{"1-ff00:0:111", "2-ff00:0:110"},
			NotMatches: []string{"1-ff00:0:110"},
		},
		"negated match wildcard": {
			Matcher:    routing.NewIAMatcher(t, "!0-0"),
			NotMatches: []string{"1-ff00:0:110"},
		},
		"negated match wildcard ISD": {
			Matcher:    routing.NewIAMatcher(t, "!0-ff00:0:110"),
			Matches:    []string{"1-ff00:0:111"},
			NotMatches: []string{"1-ff00:0:110", "2-ff00:0:110"},
		},
		"negated match wildcard AS": {
			Matcher:    routing.NewIAMatcher(t, "!1-0"),
			Matches:    []string{"2-ff00:0:110"},
			NotMatches: []string{"1-ff00:0:110", "1-ff00:0:110"},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, matches := range tc.Matches {
				assert.True(t, tc.Matcher.Match(addr.MustParseIA(matches)), matches)
			}
			for _, notMatches := range tc.NotMatches {
				assert.False(t, tc.Matcher.Match(addr.MustParseIA(notMatches)), notMatches)
			}
		})
	}
}
