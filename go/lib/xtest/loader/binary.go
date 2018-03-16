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

// Binary includes the parameters for building (and running) a Go binary.
type Binary struct {
	// Name of the package to build.
	Target string
	// Dir specifies the directory to save the binary in, and also the working
	// directory when the binary runs. If unset, the working directory of the
	// local process is used.
	Dir string
	// First part of the binary file name; the last part is generated randomly.
	Prefix string

	// Full binary path
	name string
}

// Build compiles and saves the binary.
func (b *Binary) Build() {
	b.name = Build(b.Target, b.Dir, b.Prefix)
}

// Cmd returns an initialized *exec.Cmd for the binary described by b.
// The working directory is set to b.Dir.
func (b *Binary) Cmd(args ...string) *exec.Cmd {
	if b.name == "" {
		panic("executable not found")
	}
	cmd := exec.Command(b.name, args...)
	if b.Dir != "" {
		cmd.Dir = b.Dir
	}
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

// MustTempDir creates a new temporary directory under dir with the specified
// prefix. If the function encounters an error it panics. The second return
// value is a clean-up function that can be called to recursively delete the
// entire directory.
func MustTempDir(dir, prefix string) (string, func()) {
	name, err := ioutil.TempDir(dir, prefix)
	if err != nil {
		panic(err)
	}
	return name, func() {
		os.RemoveAll(name)
	}
}
