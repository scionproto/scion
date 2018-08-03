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
	"flag"
	"fmt"
	"os"
	"strconv"

	base "github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	name       = "end2end"
	commonArgs = []string{"--data", "ping"}
	dockerArgs = []string{"tester", cmd}
	cmd        = "python/integration/end2end_test.py"
	retries    = flag.Int("retries", 0, "Number of retries before giving up.")
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	if err := integration.Init(name); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	defer log.Flush()
	clientArgs := append(commonArgs, []string{"--port", integration.ServerPortReplace, "--retries",
		strconv.Itoa(*retries), integration.SrcIAReplace, integration.DstIAReplace}...)
	serverArgs := append(commonArgs, []string{"--run_server", integration.DstIAReplace}...)
	// Redefine command and adjust args if run in docker
	if *base.Docker {
		clientArgs = append(dockerArgs, clientArgs...)
		serverArgs = append(dockerArgs, serverArgs...)
		cmd = base.DockerCmd
	}
	in := integration.NewBinaryIntegration(name, cmd, clientArgs, serverArgs)
	if err := base.RunBinaryTests(in, integration.IAPairs()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return 1
	}
	return 0
}
