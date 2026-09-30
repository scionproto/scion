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
	"bytes"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

type gitRunner func(args ...string) ([]byte, error)

func runGit(dir string) gitRunner {
	return func(args ...string) ([]byte, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git %s: %w: %s",
				strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return out, nil
	}
}

// mainlines are the branches a change is measured against, the first one present.
// A fork names the main repository upstream (doc/dev/git.rst). Its origin/master
// lags unless synced, and every upstream commit it lacks would count as a change.
var mainlines = []string{"upstream/master", "origin/master"}

func mergeBase(git gitRunner) (mainline, base string, err error) {
	for _, m := range mainlines {
		if _, err := git("rev-parse", "--verify", "--quiet", m+"^{commit}"); err != nil {
			continue
		}
		out, err := git("merge-base", "HEAD", m)
		if err != nil {
			return "", "", err
		}
		return m, strings.TrimSpace(string(out)), nil
	}
	return "", "", fmt.Errorf("found neither %s: add and fetch the main repository "+
		"as doc/dev/git.rst describes", strings.Join(mainlines, " nor "))
}

// changedFiles lists the Go files that differ between base and the working tree,
// untracked ones included and deleted ones left out.
func changedFiles(git gitRunner, base string) ([]string, error) {
	tracked, err := git("diff", "--name-only", "-z", "--no-renames", "--diff-filter=d",
		base, "--", "*.go")
	if err != nil {
		return nil, err
	}
	untracked, err := git("ls-files", "-z", "--others", "--exclude-standard", "--", "*.go")
	if err != nil {
		return nil, err
	}
	var files []string
	for f := range strings.SplitSeq(string(tracked)+string(untracked), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	slices.Sort(files)
	return files, nil
}
