// Copyright 2026 ETH Zurich
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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFirstValidGOROOT verifies that the helper returns the first valid GOROOT candidate.
func TestFirstValidGOROOT(t *testing.T) {
	// Arrange valid and invalid GOROOT candidates.
	dir := t.TempDir()
	valid1 := filepath.Join(dir, "valid1")
	valid2 := filepath.Join(dir, "valid2")
	invalid := filepath.Join(dir, "invalid")
	for _, path := range []string{valid1, valid2} {
		err := os.MkdirAll(filepath.Join(path, "src"), 0o755)
		require.NoError(t, err, "mkdir valid GOROOT %s", path)
	}
	err := os.MkdirAll(invalid, 0o755)
	require.NoError(t, err, "mkdir invalid GOROOT")

	testCases := map[string]struct {
		candidates []string
		want       string
	}{
		"valid first candidate wins": {
			candidates: []string{valid1, valid2},
			want:       valid1,
		},
		"invalid first valid second": {
			candidates: []string{invalid, valid2},
			want:       valid2,
		},
		"empty then valid": {
			candidates: []string{"", valid1},
			want:       valid1,
		},
		"all invalid or empty": {
			candidates: []string{"", invalid},
			want:       "",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Execute the helper under test.
			got := firstValidGOROOT(tc.candidates...)

			// Assert the selected candidate.
			require.Equal(t, tc.want, got)
		})
	}
}

// TestResolveGOROOT verifies that the resolver accepts valid candidates and only falls back when needed.
func TestResolveGOROOT(t *testing.T) {
	// Arrange valid and invalid GOROOT directories.
	dir := t.TempDir()
	validEnv := filepath.Join(dir, "valid-env")
	validFallback := filepath.Join(dir, "valid-fallback")
	invalidEnv := filepath.Join(dir, "invalid-env")
	invalidFallback := filepath.Join(dir, "invalid-fallback")
	for _, path := range []string{validEnv, validFallback} {
		err := os.MkdirAll(filepath.Join(path, "src"), 0o755)
		require.NoError(t, err, "mkdir valid GOROOT %s", path)
	}
	for _, path := range []string{invalidEnv, invalidFallback} {
		err := os.MkdirAll(path, 0o755)
		require.NoError(t, err, "mkdir invalid GOROOT %s", path)
	}
	runtimeValid := isValidGOROOT(runtime.GOROOT())

	testCases := map[string]struct {
		envGOROOT        string
		fallbackValue    string
		fallbackErr      error
		wantPath         func() string
		wantFallbackCall func() bool
		wantErrSubstr    string
		skipWhenRuntime  bool
	}{
		"valid environment resolves to a valid path": {
			envGOROOT: validEnv,
			wantPath: func() string {
				if runtimeValid {
					return runtime.GOROOT()
				}
				return validEnv
			},
			wantFallbackCall: func() bool { return false },
		},
		"invalid environment uses fallback when direct candidates are invalid": {
			envGOROOT:     invalidEnv,
			fallbackValue: validFallback,
			wantPath: func() string {
				return validFallback
			},
			wantFallbackCall: func() bool { return true },
			skipWhenRuntime:  true,
		},
		"empty environment uses fallback when direct candidates are invalid": {
			fallbackValue: validFallback,
			wantPath: func() string {
				return validFallback
			},
			wantFallbackCall: func() bool { return true },
			skipWhenRuntime:  true,
		},
		"fallback returning invalid path fails": {
			envGOROOT:     invalidEnv,
			fallbackValue: invalidFallback,
			wantFallbackCall: func() bool {
				return true
			},
			wantErrSubstr:   "invalid path",
			skipWhenRuntime: true,
		},
		"fallback returning empty path fails": {
			fallbackValue: "",
			wantFallbackCall: func() bool {
				return true
			},
			wantErrSubstr:   "empty result",
			skipWhenRuntime: true,
		},
		"fallback error is wrapped": {
			fallbackErr: errors.New("boom"),
			wantFallbackCall: func() bool {
				return true
			},
			wantErrSubstr:   "boom",
			skipWhenRuntime: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Cannot run in parallel with t.Parallel() due to t.SetEnv().

			// Skip fallback-only cases when runtime.GOROOT is already valid.
			if tc.skipWhenRuntime && runtimeValid {
				t.Skip("runtime.GOROOT is valid in this runner, so the fallback path is unreachable")
			}

			// Install the environment for this subtest.
			t.Setenv("GOROOT", tc.envGOROOT)

			// Stub the fallback resolver.
			fallbackCalled := false
			fallback := func() (string, error) {
				fallbackCalled = true
				return tc.fallbackValue, tc.fallbackErr
			}

			// Execute the resolver.
			got, err := resolveGOROOT(fallback)

			// Assert fallback usage.
			wantFallbackCall := tc.wantFallbackCall()
			require.Equal(t, wantFallbackCall, fallbackCalled)

			// Assert the error or resolved path.
			if tc.wantErrSubstr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			wantPath := tc.wantPath()
			require.Equal(t, wantPath, got)
			require.True(t, isValidGOROOT(got))
		})
	}
}

// TestNormalizeNewlines verifies that mixed newline styles are normalized to LF.
func TestNormalizeNewlines(t *testing.T) {
	got := string(normalizeNewlines([]byte("a\r\nb\rc\n")))
	want := "a\nb\nc\n"
	require.Equal(t, want, got)
}

// TestBuildOutputAddsHeaderAndNormalizesBody verifies that generated files get the header and LF newlines.
func TestBuildOutputAddsHeaderAndNormalizesBody(t *testing.T) {
	dir := t.TempDir()

	// Arrange a source file with CRLF line endings.
	srcPath := filepath.Join(dir, "aes_amd64.s")
	err := os.WriteFile(srcPath, []byte("// body\r\nTEXT foo\r\n"), 0o644)
	require.NoError(t, err)

	// Execute output generation for the fixture file.
	got, err := buildOutput(srcPath, filepath.Join("src", "crypto", "internal", "fips140", "aes", "aes_amd64.s"), "go-test")
	require.NoError(t, err)

	// Assert the generated header and normalized body.
	want := "// Code generated by gen_hbird_aesasm. DO NOT EDIT.\n" +
		"// Source: src/crypto/internal/fips140/aes/aes_amd64.s\n" +
		"// Go version: go-test\n\n" +
		"// body\nTEXT foo\n"
	require.Equal(t, want, string(got))
}

// TestWriteIfChanged verifies that unchanged content is not rewritten.
func TestWriteIfChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.s")
	content := []byte("same\n")

	// Write the file for the first time.
	err := writeIfChanged(path, content)
	require.NoError(t, err)
	info1, err := os.Stat(path)
	require.NoError(t, err)

	// Rewrite the same content.
	err = writeIfChanged(path, content)
	require.NoError(t, err)
	info2, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info1.ModTime().Equal(info2.ModTime()))
}

// TestCheckFile verifies that newline-normalized file contents pass freshness checking.
func TestCheckFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.s")
	content := []byte("line1\r\nline2\r\n")

	// Write a file that uses CRLF line endings.
	err := os.WriteFile(path, content, 0o644)
	require.NoError(t, err)

	// Assert that freshness checking tolerates newline normalization.
	err = checkFile(path, []byte("line1\nline2\n"))
	require.NoError(t, err)
}

// TestRunWithOutDirAndPrefix verifies that the generator writes all outputs into a custom directory.
func TestRunWithOutDirAndPrefix(t *testing.T) {
	dir := t.TempDir()
	oldGoEnv := defaultGoEnv
	defer func() {
		defaultGoEnv = oldGoEnv
	}()
	defaultGoEnv = func() (string, error) {
		return dir, nil
	}

	// Arrange a fake GOROOT with the expected AES assembly source files.
	srcDir := filepath.Join(dir, "src", "crypto", "internal", "fips140", "aes")
	err := os.MkdirAll(srcDir, 0o755)
	require.NoError(t, err)
	for _, name := range orderedSourceNames() {
		srcRel := sourceFiles[name]
		srcPath := filepath.Join(dir, srcRel)
		err := os.MkdirAll(filepath.Dir(srcPath), 0o755)
		require.NoError(t, err, "mkdir %s", srcRel)
		err = os.WriteFile(srcPath, []byte("// "+name+"\n"), 0o644)
		require.NoError(t, err, "write %s", srcRel)
	}

	// Execute the generator in custom output-directory mode.
	outDir := filepath.Join(dir, "out")
	err = run(config{outDir: outDir, prefix: "generated_"})
	require.NoError(t, err)

	// Assert that all prefixed outputs were written.
	for _, name := range orderedSourceNames() {
		got, err := os.ReadFile(filepath.Join(outDir, "generated_"+name))
		require.NoError(t, err, "read generated file %s", name)
		require.NotEmpty(t, got, "generated file %s is empty", name)
	}
}
