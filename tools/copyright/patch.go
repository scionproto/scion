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
	"io"
	"slices"
)

// contextLines is how many unchanged lines follow the edit in a hunk,
// the default of git diff. git apply refuses a hunk without context
// unless told --unidiff-zero.
const contextLines = 3

// writePatch writes the edit of one file as a git patch, to be applied from the
// repository root. [header.update] only edits the claim block at the top of the file,
// so one hunk starting at line 1 covers it.
func writePatch(w io.Writer, ch change) {
	rest := ch.rest
	// splitLines leaves an empty last element when the file ends with a line break.
	finalBreak := len(rest) > 0 && rest[len(rest)-1] == ""
	if finalBreak {
		rest = rest[:len(rest)-1]
	}
	tail := rest[:min(contextLines, len(rest))]
	body := lineDiff(ch.before, ch.after)
	for _, line := range tail {
		body = append(body, " "+line)
	}
	fmt.Fprintf(w,
		"diff --git a/%[1]s b/%[1]s\n--- a/%[1]s\n+++ b/%[1]s\n@@ -%s +%s @@\n",
		ch.file, span(len(ch.before)+len(tail)), span(len(ch.after)+len(tail)))
	for i, line := range body {
		fmt.Fprint(w, line)
		if i == len(body)-1 && len(tail) > 0 && len(tail) == len(rest) && !finalBreak {
			fmt.Fprint(w, "\n\\ No newline at end of file\n")
			continue
		}
		// A CRLF file keeps its CR in the patch, where git apply expects it.
		fmt.Fprint(w, ch.eol)
	}
}

// span is the line range of one side of a hunk that starts at the top of the file.
func span(n int) string {
	if n == 0 {
		return "0,0"
	}
	return fmt.Sprintf("1,%d", n)
}

// lineDiff returns the edit from a to b as one entry per line, prefixed with
// " ", "-" or "+", with the removals of each change ahead of its additions.
// The longest common subsequence takes quadratic time and space, which the
// few lines of a claim block can afford.
func lineDiff(a, b []string) []string {
	// lcs[i][j] is the length of the longest common subsequence of a[i:] and b[j:].
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i, v := range slices.Backward(a) {
		for j := len(b) - 1; j >= 0; j-- {
			if v == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	out := make([]string, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			out = append(out, " "+a[i])
			i++
			j++
		case j == len(b) || i < len(a) && lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, "-"+a[i])
			i++
		default:
			out = append(out, "+"+b[j])
			j++
		}
	}
	return out
}
