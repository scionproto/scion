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
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "copyright: %v\n", err)
		os.Exit(1)
	}
}

// run writes the patch to stdout and the report to stderr, which leaves stdout
// fit for git apply.
func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	affiliation := fs.String("affiliation", "",
		"organization holding copyright on the changes, "+
			"spelled as in the copyright lines")
	write := fs.Bool("w", false, "also write the patch to the files")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(),
			"usage: copyright [-w] -affiliation <organization>\n\n"+
				"Print a patch that gives the organization a current-year copyright\n"+
				"claim in every Go file that differs from where the branch left\n"+
				"upstream/master, or origin/master if there is no upstream/master.\n"+
				"Uncommitted and untracked files count. -w also applies the patch.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q: the files are the ones changed "+
			"on this branch", fs.Args())
	}
	org, err := checkAffiliation(*affiliation)
	if err != nil {
		return err
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
	rep, err := process(repo, files, org, time.Now().Year(), *write)
	if err != nil {
		return err
	}
	for _, ch := range rep.changed {
		writePatch(stdout, ch)
	}
	rep.print(stderr, mainline, writeCommand(org))
	return nil
}

// writeCommand is the go run command, from the module root, that writes the patch.
// os.Args[0] cannot give it, since go run starts a binary from a temporary path,
// but the build info names the main package. It's empty when the binary was
// built without that information.
func writeCommand(org string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	pkg, ok := strings.CutPrefix(info.Path, info.Main.Path+"/")
	if !ok {
		return ""
	}
	return fmt.Sprintf("go run ./%s -w -affiliation %q", pkg, org)
}

func checkAffiliation(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", errors.New("-affiliation is required: " +
			"name the organization holding copyright on the changes")
	case strings.ContainsAny(name, ",\r\n"):
		// [splitHolders] splits a shared line on commas.
		return "", fmt.Errorf("-affiliation %q must not contain a comma or a line break",
			name)
	}
	return name, nil
}

// change is the edit of one file. before and after are its claim block, the
// separator a new claim needs included, and rest is the remainder of the file,
// all as [splitLines] returns them.
type change struct {
	file   string
	before []string
	after  []string
	rest   []string
	eol    string
}

type report struct {
	files   int
	changed []change
	written bool
	skipped map[skipReason][]string
}

func process(
	repo string, files []string, org string, year int, write bool,
) (*report, error) {
	rep := &report{
		files:   len(files),
		written: write,
		skipped: make(map[skipReason][]string),
	}
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
		out := hdr.render(lines, claims)
		rest := lines[len(hdr.claims):]
		if write {
			if err := os.WriteFile(
				full, []byte(strings.Join(out, eol)), 0o644,
			); err != nil {
				return nil, err
			}
		}
		rep.changed = append(rep.changed, change{
			file:   file,
			before: lines[:len(hdr.claims)],
			after:  out[:len(out)-len(rest)],
			rest:   rest,
			eol:    eol,
		})
	}
	return rep, nil
}

// splitLines preserves CRLF because rewriting a header must not change every line.
func splitLines(text string) ([]string, string) {
	if strings.Contains(text, "\r\n") {
		return strings.Split(text, "\r\n"), "\r\n"
	}
	return strings.Split(text, "\n"), "\n"
}

// print writes the skipped files and a summary. A run that left the files alone
// ends with writeCmd, the command that writes the patch, or with -w if it is empty.
func (rep *report) print(w io.Writer, mainline, writeCmd string) {
	first := true
	gap := func() {
		if !first {
			fmt.Fprintln(w)
		}
		first = false
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
	verb := "would update"
	if rep.written {
		verb = "updated"
	}
	fmt.Fprintf(w, "%s %d of %s changed since the merge base with %s\n",
		verb, len(rep.changed), count(rep.files, "Go file", "Go files"), mainline)
	switch {
	case rep.written || len(rep.changed) == 0:
	case writeCmd == "":
		fmt.Fprintf(w, "rerun with -w to write the patch\n")
	default:
		fmt.Fprintf(w, "run `%s` to write the patch\n", writeCmd)
	}
}

func count(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
