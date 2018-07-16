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

package main

import (
	"fmt"
	"os"

	base "github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/integration"
)

var (
	name       = "scmp_echo"
	dockerArgs = []string{"tester", cmd}
	cmd        = "python/integration/scmp_echo_test.py"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	err := base.Setup(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup test: %s\n", err)
		return 1
	}
	clientArgs := []string{integration.SrcIAReplace, integration.DstIAReplace}
	// Redefine command and adjust args if run in docker
	if base.Docker {
		clientArgs = append(dockerArgs, clientArgs...)
		cmd = base.DockerCmd
	}
	in := integration.NewBinaryIntegration(name, cmd, clientArgs, []string{})
	if err = base.RunUnaryTests(in, integration.IAPairs()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return 1
	}
	return 0
}
