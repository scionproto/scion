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
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func main() {
	switch err := run(os.Args, os.Stdout); {
	case err == nil:
	case errors.Is(err, errOutdated):
		// The check failed, which is not a failure of the tool.
		// run already reported which files are out of date.
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "copyright: %v\n", err)
		os.Exit(2)
	}
}

// errOutdated reports that files carry stale copyright lines.
// Only main acts on it, to distinguish a failed check from a failed run.
var errOutdated = errors.New("copyright lines are out of date")

// errVerifyNeedsHistory reports -verify without the affiliation history it needs.
// affiliations.json says where people work today, so a claim held by an
// organization its contributor has since left has no contribution behind it,
// and -w would remove a line that is right.
var errVerifyNeedsHistory = errors.New("-verify needs -history: " +
	"affiliations.json says where people work today, so a claim for an " +
	"organization its contributor has since left looks unaccounted for")

type options struct {
	write     bool
	year      int
	dir       string
	history   string
	verify    bool
	skipDirty bool
	verbose   bool
	// repo is the repository root. paths are pathspecs relative to it,
	// as resolved by [locate].
	repo  string
	paths []string
}

// run reports or applies the copyright lines each file should carry.
// args is expected to be equivalent to [os.Args], and the report is written to out.
// Without -w it returns errOutdated when anything is stale,
// which makes it usable as a check.
func run(args []string, out io.Writer) error {
	var opts options
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	fs.BoolVar(&opts.write, "w", false,
		"rewrite files in place instead of only reporting")
	fs.IntVar(&opts.year, "year", time.Now().Year(),
		"year to attribute uncommitted changes to (default: current system year)")
	fs.StringVar(&opts.dir, "dir", ".",
		"directory to process, recursively (default: the current directory)")
	fs.StringVar(&opts.history, "history", "",
		"file giving the days each affiliation covered, for rewriting older "+
			"history, see README.md (default: none, affiliations.json answers "+
			"for every day)")
	fs.BoolVar(&opts.verify, "verify", false,
		"also check the claims already in the headers, and report every one "+
			"that no contribution in git history accounts for; -w removes them. "+
			"Needs -history, and holds off on files whose contributors are not "+
			"all known (default: existing claims are taken as given)")
	fs.BoolVar(&opts.skipDirty, "committed-only", false,
		"ignore uncommitted changes, considering git history alone")
	fs.BoolVar(&opts.verbose, "v", false,
		"verbose mode lists every file whose copyright lines change, "+
			"and the contribution behind each, "+
			"together with the files that were skipped")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(),
			"usage: copyright [flags] [path...]\n\n"+
				"Updates the copyright lines of Go files from git history.\n"+
				"Works on -dir and everything below it. Any path given is\n"+
				"taken relative to -dir, and narrows the run to it.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	conf, err := LoadConfig(nil)
	if err != nil {
		return err
	}
	if opts.history != "" {
		// The history stands in for the snapshot in affiliations.json,
		// which is why the two are never read together.
		if err := applyHistory(conf, opts.history); err != nil {
			return err
		}
	} else if opts.verify {
		return errVerifyNeedsHistory
	}
	resolver := conf.NewResolver()

	git, err := locate(&opts, fs.Args())
	if err != nil {
		return err
	}

	files, err := goFiles(git, opts.paths)
	if err != nil {
		return err
	}
	history, err := LoadHistory(git)
	if err != nil {
		return err
	}
	if !opts.skipDirty {
		if err := history.AddWorkingTree(git, opts.year); err != nil {
			return err
		}
	}

	rep, err := process(opts, files, history, resolver, newLogger(out, opts.verbose))
	if err != nil {
		return err
	}
	rep.print(out, opts)
	if len(rep.outdated) > 0 && !opts.write {
		return errOutdated
	}
	return nil
}

// applyHistory dates the affiliations of conf from the file at path.
func applyHistory(conf *Config, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	history, err := LoadAffiliationHistory(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := conf.ApplyHistory(history); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// newLogger reports each rewrite under -v, and discards everything otherwise.
// It writes to the report's stream, where the rest of the -v output goes.
// The timestamp is dropped: it says nothing worth reading about a run this short.
func newLogger(out io.Writer, verbose bool) *slog.Logger {
	if !verbose {
		return slog.New(slog.DiscardHandler)
	}
	return slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}

// locate resolves the repository root and the pathspecs to process, and returns
// a gitRunner bound to the root. Running git from the root keeps every reported
// path root-relative, whichever directory the tool started in.
func locate(opts *options, args []string) (gitRunner, error) {
	probe := runGit(opts.dir)
	root, err := probe("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	prefix, err := probe("rev-parse", "--show-prefix")
	if err != nil {
		return nil, err
	}
	opts.repo = strings.TrimSpace(string(root))
	opts.paths, err = scopePaths(strings.TrimSpace(string(prefix)), args)
	if err != nil {
		return nil, err
	}
	return runGit(opts.repo), nil
}

// scopePaths rebases the requested paths onto prefix, the scoped directory
// relative to the repository root. Without a path, prefix itself is the scope.
// An empty prefix is the root, and so the whole repository.
func scopePaths(prefix string, args []string) ([]string, error) {
	if len(args) == 0 {
		if prefix == "" {
			return nil, nil
		}
		return []string{prefix}, nil
	}
	paths := make([]string, 0, len(args))
	for _, arg := range args {
		if filepath.IsAbs(arg) {
			return nil, fmt.Errorf("path %q must be relative to -dir", arg)
		}
		p := filepath.ToSlash(filepath.Join(prefix, arg))
		if p == ".." || strings.HasPrefix(p, "../") {
			return nil, fmt.Errorf("path %q reaches outside the repository", arg)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// change is one file whose claims do not match its contributors.
type change struct {
	file   string
	before []string
	after  []string
	// why cites the contribution behind each claim line the update moved,
	// keyed by the rendered line. See [reasons].
	why map[string]string
}

type report struct {
	outdated []change
	skipped  map[skipReason][]string
	unmapped map[string][]string
	// unchecked lists the files -verify left the existing claims of alone,
	// because an identity that touched them has no known affiliation and could
	// be the very contributor a claim rests on.
	unchecked []string
	changed   int
}

// process brings each file's copyright lines up to date, writing them back when
// opts.write is set. Files it declines to touch are recorded with the reason.
func process(
	opts options,
	files []string,
	history *History,
	r *Resolver,
	logger *slog.Logger,
) (*report, error) {
	rep := &report{
		skipped:  make(map[skipReason][]string),
		unmapped: make(map[string][]string),
	}
	for _, file := range files {
		full := filepath.Join(opts.repo, file)
		data, err := os.ReadFile(full)
		if err != nil {
			if os.IsNotExist(err) {
				// Deleted but still in the index.
				continue
			}
			return nil, err
		}
		contributions, unmapped := history.Contributions(file, r)
		for _, email := range unmapped {
			rep.unmapped[email] = append(rep.unmapped[email], file)
		}
		if len(contributions) == 0 {
			continue
		}

		lines, eol := splitLines(string(data))
		hdr, reason := parseHeader(lines, r)
		if reason != "" {
			rep.skipped[reason] = append(rep.skipped[reason], file)
			continue
		}
		updated := hdr.update(years(contributions))
		why := reasons(hdr.claims, updated, contributions)
		if opts.verify {
			if len(unmapped) > 0 {
				rep.unchecked = append(rep.unchecked, file)
			} else {
				var doubted []string
				updated, doubted = confirm(updated, contributions)
				maps.Copy(why, doubts(hdr.claims, doubted))
			}
		}
		before, after := renderClaims(hdr.claims), renderClaims(updated)
		if slices.Equal(before, after) {
			continue
		}
		rep.outdated = append(rep.outdated, change{
			file:   file,
			before: before,
			after:  after,
			why:    why,
		})
		if !opts.write {
			continue
		}
		out := strings.Join(hdr.render(lines, updated), eol)
		info, err := os.Stat(full)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(full, []byte(out), info.Mode().Perm()); err != nil {
			return nil, err
		}
		rep.changed++
		logger.Info("rewrote", "file", file, "from", before, "to", after)
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

// renderClaims turns claims into the lines they occupy.
// A claim whose holders all moved to a newer line renders as nothing.
func renderClaims(claims []claim) []string {
	out := make([]string, 0, len(claims))
	for _, c := range claims {
		if len(c.holders) == 0 {
			continue
		}
		out = append(out, c.String())
	}
	return out
}

func (rep *report) print(w io.Writer, opts options) {
	// gap separates the sections, without opening the report on a blank line.
	first := true
	gap := func() {
		if !first {
			fmt.Fprintln(w)
		}
		first = false
	}
	if opts.verbose {
		if len(rep.outdated) > 0 {
			gap()
		}
		for _, ch := range rep.outdated {
			fmt.Fprintf(w, "%s\n", ch.file)
			for _, line := range diffLines(ch.before, ch.after) {
				why, ok := ch.why[strings.TrimPrefix(
					strings.TrimPrefix(line, "+ "), "- ",
				)]
				if !ok {
					// A dropped line is explained by the one that replaces it.
					fmt.Fprintf(w, "    %s\n", line)
					continue
				}
				fmt.Fprintf(w, "    %-*s  (%s)\n", claimWidth(ch.after), line, why)
			}
		}
		for _, reason := range slices.Sorted(maps.Keys(rep.skipped)) {
			files := rep.skipped[reason]
			gap()
			fmt.Fprintf(w, "skipped, %s (%d):\n", reason, len(files))
			for _, f := range files {
				fmt.Fprintf(w, "    %s\n", f)
			}
		}
	}
	if opts.verbose && len(rep.unchecked) > 0 {
		gap()
		fmt.Fprintf(w, "existing claims left as given, "+
			"an identity that touched them has no known affiliation (%d):\n",
			len(rep.unchecked))
		for _, f := range rep.unchecked {
			fmt.Fprintf(w, "    %s\n", f)
		}
	}
	if len(rep.unmapped) > 0 {
		gap()
		fmt.Fprintf(w, "%s no known affiliation; "+
			"their contributions are not claimed.\n",
			count(len(rep.unmapped), "identity has", "identities have"))
		fmt.Fprintf(w, "Add them to affiliations.json to attribute their work.\n")
		for _, email := range slices.Sorted(maps.Keys(rep.unmapped)) {
			files := rep.unmapped[email]
			fmt.Fprintf(w, "    %-55s %s\n", email, count(len(files), "file", "files"))
		}
	}
	gap()
	switch {
	case opts.write:
		fmt.Fprintf(w, "updated %s\n", count(rep.changed, "file", "files"))
	case len(rep.outdated) == 0:
		fmt.Fprintf(w, "all copyright lines up to date\n")
	default:
		fmt.Fprintf(w, "%s outdated copyright lines; "+
			"rerun with -w to update them\n",
			count(len(rep.outdated), "file has", "files have"))
	}
}

// claimWidth is the column the citations line up in,
// wide enough for the longest claim the file gained.
func claimWidth(after []string) int {
	width := 0
	for _, line := range after {
		if n := len(line) + len("+ "); n > width {
			width = n
		}
	}
	return width
}

func count(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// diffLines renders the change to the claim block as a -/+ listing.
// Only claim lines can differ, which is why no line-level diff is needed.
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
