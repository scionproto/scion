// Copyright 2026 SCION Association
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

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeRefs maps each remote branch to its merge base with HEAD.
func fakeRefs(refs map[string]string) gitRunner {
	return func(args ...string) ([]byte, error) {
		switch args[0] {
		case "rev-parse":
			ref := strings.TrimSuffix(args[len(args)-1], "^{commit}")
			if _, ok := refs[ref]; ok {
				return []byte("0123456789\n"), nil
			}
			return nil, fmt.Errorf("git rev-parse: exit status 1")
		case "merge-base":
			return []byte(refs[args[len(args)-1]] + "\n"), nil
		}
		return nil, fmt.Errorf("unexpected git %s", strings.Join(args, " "))
	}
}

func TestMergeBase(t *testing.T) {
	testCases := map[string]struct {
		refs     map[string]string
		mainline string
		base     string
	}{
		"a fork, whose own master lags behind": {
			refs:     map[string]string{"upstream/master": "new", "origin/master": "old"},
			mainline: "upstream/master",
			base:     "new",
		},
		"a clone of the main repository": {
			refs:     map[string]string{"origin/master": "old"},
			mainline: "origin/master",
			base:     "old",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			mainline, base, err := mergeBase(fakeRefs(tc.refs))
			require.NoError(t, err)
			require.Equal(t, tc.mainline, mainline)
			require.Equal(t, tc.base, base)
		})
	}
}

func TestMergeBaseMissing(t *testing.T) {
	_, _, err := mergeBase(fakeRefs(map[string]string{"fork/master": "x"}))
	require.Error(t, err)
}

func TestChangedFiles(t *testing.T) {
	var diff []string
	git := func(args ...string) ([]byte, error) {
		switch args[0] {
		case "diff":
			diff = args
			return []byte("b.go\x00dir/c.go\x00"), nil
		case "ls-files":
			return []byte("a.go\x00"), nil
		}
		return nil, fmt.Errorf("unexpected git %s", strings.Join(args, " "))
	}
	files, err := changedFiles(git, "5307183af")
	require.NoError(t, err)
	require.Equal(t, []string{"a.go", "b.go", "dir/c.go"}, files)
	require.Contains(t, diff, "5307183af")
}
