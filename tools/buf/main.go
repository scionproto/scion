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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/scionproto/scion/private/app/xbazel"
	"github.com/scionproto/scion/private/must"
)

func main() {
	xbazel.ChdirRoot()

	// Dynamically create the generation template. This is necessary to
	// set the correct path of the protoc-gen-connect-go binary.
	template := must.Get(json.Marshal(map[string]any{
		"version": "v2",
		"plugins": []any{
			map[string]any{
				"local": xbazel.ResolveExecutable("PATH_CONNECT"),
				"out":   "pkg",
				"opt":   "paths=source_relative",
			},
		},
	}))

	args := []string{
		"generate",
		"--template", string(template),
	}
	for _, file := range must.Get(filepath.Glob("bazel-*")) {
		args = append(args, "--exclude-path", file)
	}

	buf := exec.Command(xbazel.ResolveExecutable("PATH_BUF"), args...)
	buf.Stdin = os.Stdin
	buf.Stdout = os.Stdout
	buf.Stderr = os.Stderr

	if err := buf.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(2)
	}
}
