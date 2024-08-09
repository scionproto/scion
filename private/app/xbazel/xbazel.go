// Copyright 2024 Anapaya Systems
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

package xbazel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/scionproto/scion/private/must"
)

const binDir = "bazel-out/k8-fastbuild/bin/"

var runfilesDir = must.Get(filepath.Abs("."))

// ResolveExecutable resolves the absolute path of an executable from an
// environment variable. If the environment variable is a relative path, it is
// resolved to the CWD at initialziation time.
//
// It is safe to call this function after calling ChdirRoot.
func ResolveExecutable(env string) string {
	bin, err := resolveExecutable(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to lookup %q: %s\n", env, err)
		os.Exit(42)
	}
	return bin
}

func resolveExecutable(env string) (string, error) {
	rel := os.Getenv(env)
	if rel == "" {
		return "", fmt.Errorf("environment variable %s not set", env)
	}

	abs, err := resolveFile(rel)
	if err != nil {
		return "", fmt.Errorf("resolving executable %s: %w", rel, err)
	}

	if _, err := exec.LookPath(abs); err != nil {
		return "", fmt.Errorf("ensure executable %s: %w", abs, err)
	}
	return abs, nil
}

func resolveFile(file string) (string, error) {
	// XXX: Strip the bin directory from the file path. This is required for
	// some go binaries.
	if strings.HasPrefix(filepath.ToSlash(file), binDir) {
		var err error
		if file, err = filepath.Rel(binDir, file); err != nil {
			return "", err
		}
	}

	if !filepath.IsAbs(file) {
		file = filepath.Join(runfilesDir, file)
	}

	abs, err := filepath.Abs(file)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("ensure exists %s: %w", abs, err)
	}
	return abs, nil
}

// ChdirRoot changes the working directory to the root of the bazel workspace.
// It is safe to use ResovleExecutable after calling this function.
func ChdirRoot() {
	if bazelRoot := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); bazelRoot != "" {
		if err := os.Chdir(bazelRoot); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(43)
		}
	}
}
