// Copyright 2018 ETH Zurich
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

package loader

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

// Binary includes the parameters for building a Go binary.
type Binary struct {
	// Name of the package to build
	Target string
	// Directory where the binary should be written
	Dir string
	// First part of the binary file name
	Prefix string

	// Full binary path
	name string
}

// Build compiles and saves the binary.
func (b *Binary) Build() {
	b.name = Build(b.Target, b.Dir, b.Prefix)
}

// Run initializes exec.Cmd for the binary described by b, but does not
// actually run it. Standard output and error are inherited.
func (b *Binary) Run(args ...string) *exec.Cmd {
	if b.name == "" {
		panic("executable not found")
	}
	cmd := exec.Command(b.name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

// Build compiles package target, and saves the resulting binary in directory
// dir with a file name starting with prefix, and a randomly generated suffix.
func Build(target, dir, prefix string) string {
	binaryName := MustTempFileName(dir, prefix)

	cmd := exec.Command(
		"go", "build",
		"-o", binaryName,
		target,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Build error
		panic(fmt.Sprintf("build failed (%s)", err))
	}

	return binaryName
}

// TempFileName creates a temporary file in dir with the specified prefix, and
// then closes and deletes the file and returns its name. It is useful for
// testing packages that care about a unique path without being able to
// overwrite it (e.g., UNIX domain socket addresses or databases).
func TempFileName(dir, prefix string) (string, error) {
	file, err := ioutil.TempFile(dir, prefix)
	if err != nil {
		return "", err
	}

	name := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}

	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

// MustTempFileName is a wrapper around TempFileName. The function panics if an
// error occurs. It is intended for tests where error handling is not
// necessary, and for chaining functions.
func MustTempFileName(dir, prefix string) string {
	name, err := TempFileName(dir, prefix)
	if err != nil {
		panic(err)
	}
	return name
}
