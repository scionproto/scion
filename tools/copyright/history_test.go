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

// fakeGit answers each git subcommand from a canned string.
func fakeGit(out map[string]string) gitRunner {
	return func(args ...string) ([]byte, error) {
		if canned, ok := out[args[0]]; ok {
			return []byte(canned), nil
		}
		return nil, fmt.Errorf("unexpected git %s", strings.Join(args, " "))
	}
}

// commit renders one revision in the --name-status form [LoadHistory] parses,
// dated the first of January. Use [commitOn] where the day matters.
func commit(hash, email string, year int, entries ...string) string {
	return commitOn(hash, email, fmt.Sprintf("%d-01-01", year), entries...)
}

func commitOn(hash, email, date string, entries ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\x00%s\x1f%s\x1f%s\n\n", hash, email, date)
	for _, e := range entries {
		fmt.Fprintf(&b, "%s\n", e)
	}
	return b.String()
}

// on is the source a [commit] of that year records.
func on(year int, hash string) source {
	return source{date: fmt.Sprintf("%d-01-01", year), commit: hash}
}

// TestLoadHistory checks that every change is attributed to the file's
// present-day path, across two renames.
func TestLoadHistory(t *testing.T) {
	// Newest first, as git log prints them.
	log := commit("h4", "new@scion.org", 2026, "M\tnow/here.go") +
		commit("h3", "mid@anapaya.net", 2024, "R092\twas/there.go\tnow/here.go") +
		commit("h2", "old@anapaya.net", 2020, "M\twas/there.go", "A\tother.go") +
		commit("h1", "old@anapaya.net", 2019, "R100\toriginal.go\twas/there.go")

	h, err := LoadHistory(fakeGit(map[string]string{"log": log}))
	require.NoError(t, err)

	require.Equal(t, map[contribution]source{
		{email: "new@scion.org", year: 2026}:   on(2026, "h4"),
		{email: "mid@anapaya.net", year: 2024}: on(2024, "h3"),
		{email: "old@anapaya.net", year: 2020}: on(2020, "h2"),
		{email: "old@anapaya.net", year: 2019}: on(2019, "h1"),
	}, h.byFile["now/here.go"], "renames followed to the present name")
	require.Equal(t, map[contribution]source{
		{email: "old@anapaya.net", year: 2020}: on(2020, "h2"),
	}, h.byFile["other.go"])
	require.NotContains(t, h.byFile, "was/there.go")
	require.NotContains(t, h.byFile, "original.go")
}

// TestLoadHistoryCopy checks that a copy attributes only the new file.
func TestLoadHistoryCopy(t *testing.T) {
	log := commit("h1", "who@scion.org", 2026, "C080\tsource.go\tcopy.go")
	h, err := LoadHistory(fakeGit(map[string]string{"log": log}))
	require.NoError(t, err)
	require.Contains(t, h.byFile, "copy.go")
	require.NotContains(t, h.byFile, "source.go")
}

// TestLoadHistoryMalformed checks that unparseable output is an error rather
// than a silently empty history.
func TestLoadHistoryMalformed(t *testing.T) {
	_, err := LoadHistory(fakeGit(map[string]string{"log": "\x00h1\x1fwho@scion.org\n"}))
	require.Error(t, err)
	_, err = LoadHistory(fakeGit(map[string]string{"log": "\x00h1\x1fwho@scion.org\x1flast\n"}))
	require.Error(t, err)
}

// TestContributions covers the years each organization gets,
// and the identities that need adding to the configuration.
func TestContributions(t *testing.T) {
	log := commit("h5", "stranger@example.com", 2026, "M\tfile.go") +
		commit("h4", "bot@example.com", 2026, "M\tfile.go") +
		commit("h3", "mover@example.com", 2025, "M\tfile.go") +
		commit("h2", "mover@example.com", 2019, "M\tfile.go") +
		commit("h1", "who@anapaya.net", 2020, "A\tfile.go")

	h, err := LoadHistory(fakeGit(map[string]string{"log": log}))
	require.NoError(t, err)

	orgs, unmapped := h.Contributions("file.go", testResolver(t))
	require.Equal(t, map[string]attribution{
		"SCION Association": {year: 2025, email: "mover@example.com", source: on(2025, "h3")},
		"ETH Zurich":        {year: 2019, email: "mover@example.com", source: on(2019, "h2")},
		"Anapaya Systems":   {year: 2020, email: "who@anapaya.net", source: on(2020, "h1")},
	}, orgs)
	require.Equal(t, []string{"stranger@example.com"}, unmapped,
		"the bot is excluded on purpose, and the mover is known")
}

// TestAddWorkingTree checks that uncommitted work counts.
// A file must get its copyright line in the same change that edits it.
func TestAddWorkingTree(t *testing.T) {
	status := strings.Join([]string{
		" M modified.go",
		"?? untracked.go",
		"A  added.go",
		"R  renamed.go", "old.go",
		"MM staged-and-dirty.go",
	}, "\x00") + "\x00"

	h := newHistory()
	git := fakeGit(map[string]string{
		"status": status,
		"config": "who@scion.org\n",
	})
	require.NoError(t, h.AddWorkingTree(git, 2026))

	me := map[contribution]source{{email: "who@scion.org", year: 2026}: {}}
	for _, file := range []string{
		"modified.go", "untracked.go", "added.go", "renamed.go", "staged-and-dirty.go",
	} {
		require.Equal(t, me, h.byFile[file], file)
	}
	require.NotContains(t, h.byFile, "old.go",
		"the pre-rename name is not a file any more")
}

// TestAddWorkingTreeWithoutIdentity checks that uncommitted work with no
// user.email to attribute it to stops the run instead of going unattributed.
func TestAddWorkingTreeWithoutIdentity(t *testing.T) {
	status := " M modified.go\x00"
	for name, config := range map[string]string{
		"unset": "",
		"empty": "  \n",
	} {
		t.Run(name, func(t *testing.T) {
			out := map[string]string{"status": status}
			if config != "" {
				// git config exits non-zero when the key is unset, which
				// fakeGit does for any subcommand it has no answer for.
				out["config"] = config
			}
			h := newHistory()
			require.ErrorIs(t, h.AddWorkingTree(fakeGit(out), 2026), errNoIdentity)
			require.Empty(t, h.byFile)
		})
	}
}

// TestAddWorkingTreeCleanNeedsNoIdentity checks that user.email is only
// required when there is uncommitted work to attribute.
func TestAddWorkingTreeCleanNeedsNoIdentity(t *testing.T) {
	h := newHistory()
	require.NoError(t, h.AddWorkingTree(fakeGit(map[string]string{"status": ""}), 2026))
	require.Empty(t, h.byFile)
}

// TestContributionsCitesNewestEvidence checks which contribution an
// organization's claim is credited to when several could carry it.
func TestContributionsCitesNewestEvidence(t *testing.T) {
	log := commitOn("h3", "b@scion.org", "2025-03-04", "M\tfile.go") +
		commitOn("h2", "a@scion.org", "2025-11-30", "M\tfile.go") +
		commitOn("h1", "a@scion.org", "2024-01-01", "M\tfile.go")
	h, err := LoadHistory(fakeGit(map[string]string{"log": log}))
	require.NoError(t, err)

	orgs, _ := h.Contributions("file.go", testResolver(t))
	require.Equal(t, attribution{
		year: 2025, email: "a@scion.org",
		source: source{date: "2025-11-30", commit: "h2"},
	}, orgs["SCION Association"],
		"the latest day of the claimed year, not the latest commit in the log")

	// Uncommitted work outranks anything committed, whoever made it.
	require.NoError(t, h.AddWorkingTree(fakeGit(map[string]string{
		"status": " M file.go\x00",
		"config": "c@scion.org\n",
	}), 2025))
	orgs, _ = h.Contributions("file.go", testResolver(t))
	require.Equal(t, attribution{year: 2025, email: "c@scion.org"},
		orgs["SCION Association"])
}

// TestContributionsKeepsNewestCommitPerIdentity checks that the older of two
// commits by one identity in one year is not what gets cited.
func TestContributionsKeepsNewestCommitPerIdentity(t *testing.T) {
	log := commitOn("h2", "a@scion.org", "2025-11-30", "M\tfile.go") +
		commitOn("h1", "a@scion.org", "2025-03-04", "M\tfile.go")
	h, err := LoadHistory(fakeGit(map[string]string{"log": log}))
	require.NoError(t, err)
	require.Equal(t, source{date: "2025-11-30", commit: "h2"},
		h.byFile["file.go"][contribution{email: "a@scion.org", year: 2025}])
}

// TestGoFiles checks that only Go files are considered, without duplicates.
func TestGoFiles(t *testing.T) {
	listing := strings.Join([]string{
		"b.go", "a.go", "a.go", "notes.md", "BUILD.bazel", "dir/c.go",
	}, "\x00") + "\x00"
	files, err := goFiles(fakeGit(map[string]string{"ls-files": listing}), nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a.go", "b.go", "dir/c.go"}, files)
}

func TestScopePaths(t *testing.T) {
	testCases := map[string]struct {
		prefix string
		args   []string
		want   []string
		err    bool
	}{
		"whole repository": {prefix: "", args: nil, want: nil},
		"a subtree":        {prefix: "router/", args: nil, want: []string{"router/"}},
		"paths at the root": {
			prefix: "", args: []string{"router", "pkg/slayers"},
			want: []string{"router", "pkg/slayers"},
		},
		"paths within a subtree": {
			prefix: "router/", args: []string{"dataplane.go", "mgmtapi"},
			want: []string{"router/dataplane.go", "router/mgmtapi"},
		},
		"a path is cleaned": {
			prefix: "router/", args: []string{"./bfd/../svc.go"},
			want: []string{"router/svc.go"},
		},
		"a sibling directory": {
			prefix: "router/", args: []string{"../pkg/slayers"},
			want: []string{"pkg/slayers"},
		},

		"reaching outside the repository": {
			prefix: "", args: []string{"../elsewhere"}, err: true,
		},
		"an absolute path": {
			prefix: "", args: []string{"/etc"}, err: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			got, err := scopePaths(tc.prefix, tc.args)
			if tc.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
