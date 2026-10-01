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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// patchOf returns the patch that gives SCION Association its 2026 claim in a
// file holding content.
func patchOf(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f.go"), []byte(content), 0o644))
	rep, err := process(dir, []string{"f.go"}, "SCION Association", 2026, false)
	require.NoError(t, err)
	require.Len(t, rep.changed, 1)
	var b strings.Builder
	writePatch(&b, rep.changed[0])
	return b.String()
}

const patchHeader = "diff --git a/f.go b/f.go\n--- a/f.go\n+++ b/f.go\n"

func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

func TestWritePatch(t *testing.T) {
	testCases := map[string]struct {
		file  string
		patch string
	}{
		"claim and separator inserted above a license opening the file": {
			file: strings.TrimPrefix(licenseBlock, "//\n"),
			// The last context line is the empty line below the license,
			// which a patch writes as a lone space.
			patch: patchHeader + "@@ -1,3 +1,5 @@\n" +
				"+// Copyright 2026 SCION Association\n" +
				"+//\n" +
				" // Licensed under the Apache License, " +
				"Version 2.0 (the \"License\");\n" +
				" // you may not use this file except in compliance with the License.\n" +
				" \n",
		},
		"no line break at the end of the file": {
			file: "// Copyright 2025 SCION Association\n//\npackage main",
			patch: patchHeader + `@@ -1,3 +1,3 @@
-// Copyright 2025 SCION Association
+// Copyright 2026 SCION Association
 //
 package main
\ No newline at end of file
`,
		},
		"crlf kept in the lines of the hunk": {
			file: crlf("// Copyright 2025 SCION Association\n" + licenseBlock),
			patch: patchHeader + "@@ -1,4 +1,4 @@\n" + crlf(`-// Copyright 2025 SCION Association
+// Copyright 2026 SCION Association
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
`),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.patch, patchOf(t, tc.file))
		})
	}
}

func TestLineDiff(t *testing.T) {
	assert.Equal(t, []string{
		"-// Copyright 2017 ETH Zurich",
		"-// Copyright 2018 ETH Zurich, Anapaya Systems",
		"+// Copyright 2026 ETH Zurich",
		"+// Copyright 2018 Anapaya Systems",
		" // Copyright 2025 SCION Association",
	}, lineDiff([]string{
		"// Copyright 2017 ETH Zurich",
		"// Copyright 2018 ETH Zurich, Anapaya Systems",
		"// Copyright 2025 SCION Association",
	}, []string{
		"// Copyright 2026 ETH Zurich",
		"// Copyright 2018 Anapaya Systems",
		"// Copyright 2025 SCION Association",
	}))
}
