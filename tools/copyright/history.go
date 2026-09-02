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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// contribution is one identity's work on a file, on the day it is dated.
// The day resolves which organization the author belonged to,
// which can change mid-year; its year is what a claim states.
type contribution struct {
	email string
	date  string // YYYY-MM-DD
}

// year is the year a claim for this contribution states.
// [History.add] admits no date it cannot be read from.
func (c contribution) year() int {
	year, _ := strconv.Atoi(c.date[:4])
	return year
}

// source is where a contribution was seen. The zero value is the working tree,
// which has neither a date nor a commit to point at.
type source struct {
	date   string // YYYY-MM-DD
	commit string // abbreviated hash
}

// History records, per file, the days each identity touched it,
// and where the most recent evidence for each of those contributions sits.
type History struct {
	// byFile is keyed by present-day path: [LoadHistory] resolves historical
	// paths through renames before recording them.
	byFile map[string]map[contribution]source
}

func newHistory() *History {
	return &History{byFile: make(map[string]map[contribution]source)}
}

// add drops incomplete entries: an unset author or date would claim copyright for nobody.
// Revisions arrive newest first, so the first source recorded for a contribution
// is its newest commit. Uncommitted work is newer still, and overwrites.
func (h *History) add(file, email, date string, where source) {
	if file == "" || email == "" || len(date) < len("YYYY") {
		return
	}
	set, ok := h.byFile[file]
	if !ok {
		set = make(map[contribution]source)
		h.byFile[file] = set
	}
	c := contribution{email: email, date: date}
	if _, seen := set[c]; seen && where.commit != "" {
		return
	}
	set[c] = where
}

// attribution is the newest contribution an organization made to a file.
// It is the evidence a claim's year rests on, and what the report cites.
type attribution struct {
	year  int
	email string
	source
}

func (a attribution) String() string {
	if a.commit == "" {
		return fmt.Sprintf("%s, uncommitted", a.email)
	}
	return fmt.Sprintf("%s, %s %s", a.email, a.date, a.commit)
}

// newer reports whether a is more recent evidence than b.
// Uncommitted work beats anything committed.
// The comparison is total, so a run reports the same evidence every time.
func (a attribution) newer(b attribution) bool {
	switch {
	case a.year != b.year:
		return a.year > b.year
	case (a.commit == "") != (b.commit == ""):
		return a.commit == ""
	case a.date != b.date:
		return a.date > b.date
	default:
		return a.commit > b.commit
	}
}

// Contributions returns the newest contribution each organization made to file,
// and the identities the configuration has never heard of.
func (h *History) Contributions(file string, r *Resolver) (map[string]attribution, []string) {
	orgs := make(map[string]attribution)
	unmapped := make(map[string]struct{})
	for c, where := range h.byFile[file] {
		org, ok := r.Org(c.email, c.date)
		if !ok {
			if !r.Known(c.email) {
				unmapped[c.email] = struct{}{}
			}
			continue
		}
		a := attribution{year: c.year(), email: c.email, source: where}
		if best, seen := orgs[org]; seen && !a.newer(best) {
			continue
		}
		orgs[org] = a
	}
	return orgs, slices.Sorted(maps.Keys(unmapped))
}

// years reduces attributions to the year each organization claims.
// The claim algebra in header.go needs no more than that.
func years(attr map[string]attribution) map[string]int {
	out := make(map[string]int, len(attr))
	for org, a := range attr {
		out[org] = a.year
	}
	return out
}

// gitRunner runs one git subcommand and returns its stdout.
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

// LoadHistory walks the whole history once and attributes every change to the
// file's present-day path, following renames. One pass over this repository's
// 5700 revisions takes about 0.5s, against about 0.1s per file for --follow.
func LoadHistory(git gitRunner) (*History, error) {
	out, err := git("log", "--format=%x00%h%x1f%ae%x1f%ad", "--date=short",
		"--name-status", "-M", "HEAD")
	if err != nil {
		return nil, err
	}
	h := newHistory()
	// Revisions arrive newest first. A rename is therefore seen before the
	// revisions that used the old name. present maps a historical path to today's.
	present := make(map[string]string)
	resolve := func(p string) string {
		if q, ok := present[p]; ok {
			return q
		}
		return p
	}

	var email, date string
	var where source
	var renames [][2]string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "\x00") {
			// A revision's renames apply only to older revisions.
			applyRenames(present, resolve, renames)
			renames = renames[:0]
			fields := strings.Split(strings.TrimPrefix(line, "\x00"), "\x1f")
			if len(fields) != 3 {
				return nil, fmt.Errorf("malformed git log header: %q", line)
			}
			email, date = fields[1], fields[2]
			// A malformed date would compare wrongly against the spans in
			// affiliations.json, and silently attribute the work elsewhere.
			if _, err := time.Parse(time.DateOnly, date); err != nil {
				return nil, fmt.Errorf("malformed date in %q: %w", line, err)
			}
			where = source{date: date, commit: fields[0]}
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		switch {
		case len(fields) == 2:
			h.add(resolve(fields[1]), email, date, where)
		case len(fields) == 3 && strings.HasPrefix(fields[0], "R"):
			h.add(resolve(fields[2]), email, date, where)
			renames = append(renames, [2]string{fields[1], fields[2]})
		case len(fields) == 3 && strings.HasPrefix(fields[0], "C"):
			// A copy leaves the original untouched.
			h.add(resolve(fields[2]), email, date, where)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading git log: %w", err)
	}
	applyRenames(present, resolve, renames)
	return h, nil
}

// applyRenames records that each new path went by its old name earlier in history.
func applyRenames(present map[string]string, resolve func(string) string, renames [][2]string) {
	for _, r := range renames {
		present[r[0]] = resolve(r[1])
	}
}

// AddWorkingTree attributes staged, unstaged and untracked changes to the
// current user in the current year. Such work carries no date of its own,
// so the author's affiliation is read at the end of the year it is claimed for,
// the newest day that year can stand for.
// Work in progress is what most often needs a fresh copyright line.
// The identity is only looked up once there is such work, so a clean tree needs none.
func (h *History) AddWorkingTree(git gitRunner, year int) error {
	files, err := dirtyFiles(git)
	if err != nil || len(files) == 0 {
		return err
	}
	email, err := currentEmail(git)
	if err != nil {
		return err
	}
	date := fmt.Sprintf("%d-12-31", year)
	for _, file := range files {
		h.add(file, email, date, source{})
	}
	return nil
}

// dirtyFiles lists the files with staged, unstaged or untracked changes.
func dirtyFiles(git gitRunner) ([]string, error) {
	out, err := git("status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return nil, err
	}
	var files []string
	fields := strings.Split(string(out), "\x00")
	for i := 0; i < len(fields); i++ {
		entry := fields[i]
		if len(entry) < 4 {
			continue
		}
		status, file := entry[:2], entry[3:]
		files = append(files, file)
		if status[0] == 'R' || status[0] == 'C' {
			// A rename or copy entry is followed by the original path.
			i++
		}
	}
	return files, nil
}

// errNoIdentity reports that there is uncommitted work but nobody to credit for it.
// Stopping is better than the alternative, which is a run that quietly
// leaves the working tree out and reports every header as up to date.
var errNoIdentity = errors.New("git config user.email is not set, " +
	"so uncommitted changes cannot be attributed to anyone; " +
	"set it, or pass -committed-only to consider git history alone")

// currentEmail is the identity to credit for uncommitted work.
func currentEmail(git gitRunner) (string, error) {
	// git config exits non-zero when the key is unset,
	// which says no more than an empty value does.
	out, err := git("config", "--get", "user.email")
	if err != nil {
		return "", errNoIdentity
	}
	email := strings.TrimSpace(string(out))
	if email == "" {
		return "", errNoIdentity
	}
	return email, nil
}

// goFiles lists the Go files under the given pathspecs, or every Go file in the
// repository when none is given. Untracked files are included.
func goFiles(git gitRunner, paths []string) ([]string, error) {
	args := []string{"ls-files", "-z", "--cached", "--others", "--exclude-standard", "--"}
	if len(paths) == 0 {
		args = append(args, "*.go")
	} else {
		args = append(args, paths...)
	}
	out, err := git(args...)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for f := range strings.SplitSeq(string(out), "\x00") {
		if strings.HasSuffix(f, ".go") {
			seen[f] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(seen)), nil
}
