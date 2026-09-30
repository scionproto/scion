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
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "copyright: %v\n", err)
		os.Exit(1)
	}
}

// run is main without [os.Exit]. args has the shape of [os.Args].
func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	affiliation := fs.String("affiliation", "",
		"organization holding copyright on the changes, one of: "+
			strings.Join(organizations, ", "))
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(),
			"usage: copyright -affiliation <organization>\n\n"+
				"Gives the organization a copyright claim for the current year in every\n"+
				"Go file that differs from where the branch left upstream/master, or\n"+
				"origin/master if there is no upstream/master. Uncommitted and\n"+
				"untracked files count.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q: the files are the ones changed "+
			"on this branch", fs.Args())
	}
	org, ok := knownOrg(*affiliation)
	switch {
	case *affiliation == "":
		return fmt.Errorf("-affiliation is required, one of: %s",
			strings.Join(organizations, ", "))
	case !ok:
		return fmt.Errorf("-affiliation %q is not in organizations.go: add it there, "+
			"or name one of: %s", *affiliation, strings.Join(organizations, ", "))
	}

	// bazel run starts the tool in its runfiles tree, outside the repository, and
	// names the workspace in BUILD_WORKSPACE_DIRECTORY:
	// https://bazel.build/docs/user-manual#running-executables
	dir := "."
	if ws := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); ws != "" {
		dir = ws
	}
	root, err := runGit(dir)("rev-parse", "--show-toplevel")
	if err != nil {
		return err
	}
	// Running git from the root keeps every path it prints root-relative.
	repo := strings.TrimSpace(string(root))
	git := runGit(repo)
	mainline, base, err := mergeBase(git)
	if err != nil {
		return err
	}
	files, err := changedFiles(git, base)
	if err != nil {
		return err
	}
	rep, err := process(repo, files, org, time.Now().Year())
	if err != nil {
		return err
	}
	rep.print(out, mainline)
	return nil
}

// change is one file whose claims were updated.
type change struct {
	file   string
	before []string
	after  []string
}

type report struct {
	files   int
	changed []change
	skipped map[skipReason][]string
}

// process gives org a claim for year in each of files, which are relative to repo.
func process(repo string, files []string, org string, year int) (*report, error) {
	rep := &report{files: len(files), skipped: make(map[skipReason][]string)}
	for _, file := range files {
		full := filepath.Join(repo, file)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, err
		}
		lines, eol := splitLines(string(data))
		hdr, reason := parseHeader(lines)
		if reason != "" {
			rep.skipped[reason] = append(rep.skipped[reason], file)
			continue
		}
		claims := hdr.update(lines, org, year)
		if claims == nil {
			continue
		}
		out := strings.Join(hdr.render(lines, claims), eol)
		if err := os.WriteFile(full, []byte(out), 0o644); err != nil {
			return nil, err
		}
		rep.changed = append(rep.changed, change{
			file:   file,
			before: lines[:len(hdr.claims)],
			after:  claims,
		})
	}
	return rep, nil
}

// splitLines returns the lines of text and the line ending it used.
// A rewrite must not convert CRLF to LF as a side effect.
func splitLines(text string) ([]string, string) {
	if strings.Contains(text, "\r\n") {
		return strings.Split(text, "\r\n"), "\r\n"
	}
	return strings.Split(text, "\n"), "\n"
}

func (rep *report) print(w io.Writer, mainline string) {
	first := true
	gap := func() {
		if !first {
			fmt.Fprintln(w)
		}
		first = false
	}
	if len(rep.changed) > 0 {
		gap()
	}
	for _, ch := range rep.changed {
		fmt.Fprintf(w, "%s\n", ch.file)
		for _, line := range diffLines(ch.before, ch.after) {
			fmt.Fprintf(w, "    %s\n", line)
		}
	}
	for _, reason := range slices.Sorted(maps.Keys(rep.skipped)) {
		files := rep.skipped[reason]
		gap()
		fmt.Fprintf(w, "left alone, %s (%d):\n", reason, len(files))
		for _, f := range files {
			fmt.Fprintf(w, "    %s\n", f)
		}
	}
	gap()
	if rep.files == 0 {
		fmt.Fprintf(w, "no Go files changed since the merge base with %s\n", mainline)
		return
	}
	fmt.Fprintf(w, "updated %d of %s changed since the merge base with %s\n",
		len(rep.changed), count(rep.files, "Go file", "Go files"), mainline)
}

func count(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// diffLines renders the change to the claim block as a -/+ listing.
// [header.update] replaces or appends at most one line and never reorders,
// which makes a set difference enough.
func diffLines(before, after []string) []string {
	old := make(map[string]bool, len(before))
	for _, line := range before {
		old[line] = true
	}
	fresh := make(map[string]bool, len(after))
	for _, line := range after {
		fresh[line] = true
	}
	var out []string
	for _, line := range before {
		if !fresh[line] {
			out = append(out, "- "+line)
		}
	}
	for _, line := range after {
		if !old[line] {
			out = append(out, "+ "+line)
		}
	}
	return out
}
