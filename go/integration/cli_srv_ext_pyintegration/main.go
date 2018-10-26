// Copyright 2018 ETH Zurich, Anapaya Systems
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

	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	name = "cli_srv_ext"
	cmd  = "python/integration/cli_srv_ext_test.py"
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
	clientArgs := []string{"--port", integration.ServerPortReplace, "-c",
		integration.SrcHostReplace, "-s", integration.DstHostReplace, integration.SrcIAReplace,
		integration.DstIAReplace}
	serverArgs := []string{"--run_server", "-s", integration.DstHostReplace,
		integration.DstIAReplace}
	in := integration.NewBinaryIntegration(name, cmd, clientArgs, serverArgs)
	if err := integration.RunBinaryTests(in,
		integration.IAPairs(integration.DispAddr)); err != nil {
		log.Error("Error during tests", "err", err)
		return 1
	}
	return 0
}
