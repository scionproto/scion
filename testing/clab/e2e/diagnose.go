// Copyright 2026 Anapaya Systems
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

package e2e

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// SnapshotPaths runs `scion showpaths --extended` from src to dst inside the
// src node and returns its combined output. It is meant to be called right
// after a probe fails, to capture the path state (which paths exist and their
// liveness) as close as possible to the failure. Errors are folded into the
// returned text; the snapshot is best-effort diagnostics.
func SnapshotPaths(docker Docker, scionBin string, src, dst Endpoint, timeout time.Duration) string {
	// Give the command a bit of slack beyond the scion timeout for docker exec.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	bin, argv := docker.Exec(src.Container, scionBin, "showpaths", dst.IA,
		"--sciond", src.SciondAddr(), "--extended", "--timeout", timeout.String())
	out, err := exec.CommandContext(ctx, bin, argv...).CombinedOutput()
	s := string(out)
	if err != nil {
		s += fmt.Sprintf("\n(showpaths failed: %s)", err)
	}
	return s
}

// Failure is a failed probe, as rendered by PrintFailures.
type Failure struct {
	Src, Dst Endpoint
	Err      error
	// Output is the combined output of the failed probe command.
	Output string
	// Paths is the path snapshot taken right after the failure (see
	// SnapshotPaths). Empty if none was taken.
	Paths string
}

// SortFailures sorts the failures by source, then destination ISD-AS.
func SortFailures(fails []Failure) {
	slices.SortFunc(fails, func(a, b Failure) int {
		if c := strings.Compare(a.Src.IA, b.Src.IA); c != 0 {
			return c
		}
		return strings.Compare(a.Dst.IA, b.Dst.IA)
	})
}

// PrintFailures prints the failures, each with the probe's full output and
// the path snapshot taken at failure time. Nothing is printed for an empty
// list.
func PrintFailures(w io.Writer, fails []Failure) {
	if len(fails) == 0 {
		return
	}
	fmt.Fprintf(w, "  failures:\n")
	for _, f := range fails {
		fmt.Fprintf(w, "    %s -> %s: %v\n", f.Src.IA, f.Dst.IA, f.Err)
		fmt.Fprintf(w, "      output:\n%s", indent(f.Output, "        "))
		if f.Paths != "" {
			fmt.Fprintf(w, "      paths at failure (showpaths --extended):\n%s",
				indent(f.Paths, "        "))
		}
	}
}

// indent prefixes every line of s and terminates the result with a newline.
// Empty input renders as "<empty>".
func indent(s, prefix string) string {
	s = strings.TrimRight(s, "\n")
	if strings.TrimSpace(s) == "" {
		return prefix + "<empty>\n"
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}
