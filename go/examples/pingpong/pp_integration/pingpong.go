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

	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	if err := integration.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	asList, err := integration.LoadASList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AS-list: %s\n", err)
		return 1
	}
	// TODO(lukedirtwalker) we should enable logging
	// depeding on the main log parameter it should either go to a file or to console stderr.
	in := integration.NewBinaryIntegration("./bin/pingpong",
		[]string{"-mode", "client", "-sciondFromIA", "-count", "1",
			"-local", integration.LocalAddrReplace + ",[127.0.0.1]:0",
			"-remote", integration.RemoteAddrReplace + ",[127.0.0.1]:40004"},
		[]string{"-mode", "server", "-sciondFromIA",
			"-local", integration.LocalAddrReplace + ",[127.0.0.1]:40004"})
	if err = integration.RunTests(in, integration.GenerateAllSrcDst(asList)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return 1
	}
	return 0
}
