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

	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	name       = "end2end"
	cmd        = "./bin/end2end"
	dockerArgs = []string{"tester", cmd}
	attempts   = flag.Int("attempts", 1, "Number of attempts before giving up.")
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
	clientAddr := integration.SrcIAReplace + ",[127.0.0.1]:0"
	serverAddr := integration.DstIAReplace + ",[127.0.0.1]:" + integration.ServerPortReplace
	clientArgs := []string{"-log.console", "debug", "-attempts", strconv.Itoa(*attempts),
		"-local", clientAddr, "-remote", serverAddr}
	serverArgs := []string{"-log.console", "debug", "-mode", "server", "-local", serverAddr}
	// Redefine command and adjust args if run in docker
	if *integration.Docker {
		clientArgs = append(dockerArgs, clientArgs...)
		serverArgs = append(dockerArgs, serverArgs...)
		cmd = integration.DockerCmd
	}
	in := integration.NewBinaryIntegration(name, cmd, clientArgs, serverArgs, integration.StdLog)
	if err := runTests(in, integration.IAPairs()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return 1
	}
	return 0
}

// RunTests runs the client and server for each IAPair.
// In case of an error the function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	// First run all servers
	dsts := integration.ExtractUniqueDsts(pairs)
	for _, dst := range dsts {
		c, err := integration.StartServer(in, dst)
		if err != nil {
			return err
		}
		defer c.Close()
	}
	if err := integration.RunUnaryTests(in, integration.IAPairs()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return err
	}
	return nil
}
