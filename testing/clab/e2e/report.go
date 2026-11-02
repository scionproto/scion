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
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// PrintMatrix renders the src×dst result grid for the given endpoints. Columns
// are AS indices; rows are labeled with both the index and the ISD-AS so the
// header stays compact. The cell function reports the outcome of the src→dst
// probe; same-source-and-destination cells are rendered as "·" without calling
// it.
func PrintMatrix(eps []Endpoint, cell func(src, dst Endpoint) bool) {
	idx := make(map[string]int, len(eps))
	for i, e := range eps {
		idx[e.IA] = i + 1
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	header := []string{"  src \\ dst"}
	for i := range eps {
		header = append(header, fmt.Sprint(i+1))
	}
	fmt.Fprintln(tw, strings.Join(header, "\t"))

	for _, src := range eps {
		row := []string{fmt.Sprintf("%d %s", idx[src.IA], src.IA)}
		for _, dst := range eps {
			switch {
			case src.IA == dst.IA:
				row = append(row, "·")
			case cell(src, dst):
				row = append(row, "✓")
			default:
				row = append(row, "✗")
			}
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
}

// FirstLine returns the first non-empty line of s, trimmed.
func FirstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
