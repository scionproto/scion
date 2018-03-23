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
	"os"
	"os/exec"

	"github.com/scionproto/scion/go/lib/xtest"
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
	// Extra build flags
	BuildFlags []string

	// Full binary path
	name string
}

// Build compiles and saves the binary.
func (b *Binary) Build() error {
	name, err := Build(b.Target, b.Dir, b.Prefix, b.BuildFlags...)
	if err != nil {
		return err
	}
	b.name = name
	return nil
}

// Cmd returns an initialized *exec.Cmd for the binary described by b.
// The working directory is set to b.Dir.
func (b *Binary) Cmd(args ...string) *exec.Cmd {
	cmd := exec.Command(b.name, args...)
	if b.Dir != "" {
		cmd.Dir = b.Dir
	}
	return cmd
}

// Build compiles package target, and saves the resulting binary in directory
// dir with a file name starting with prefix, and a randomly generated suffix.
// On errors, the first returned value is "" and the error is non-nil.
func Build(target, dir, prefix string, extraFlags ...string) (string, error) {
	binaryName := xtest.MustTempFileName(dir, prefix)

	args := append(append([]string{"build", "-o", binaryName}, extraFlags...), target)
	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Build error
		return "", fmt.Errorf("build failed (%s)", err)
	}
	return binaryName, nil
}
