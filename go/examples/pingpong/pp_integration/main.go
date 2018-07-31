// Copyright 2018 Anapaya Systems
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
	"time"

	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

const (
	serverPort = "40004"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	if err := integration.Init("pp_integration"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	defer log.Flush()
	in := integration.NewBinaryIntegration("./bin/pingpong",
		[]string{"-mode", "client", "-sciondFromIA", "-log.console", "debug", "-count", "1",
			"-local", integration.SrcIAReplace + ",[127.0.0.1]:0",
			"-remote", integration.DstIAReplace + ",[127.0.0.1]:" + serverPort},
		[]string{"-mode", "server", "-sciondFromIA", "-log.console", "debug",
			"-local", integration.DstIAReplace + ",[127.0.0.1]:" + serverPort})
	if err := runTests(in, integration.IAPairs()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return 1
	}
	return 0
}

// RunTests runs the client and server for each IAPair.
// In case of an error the function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name(), func() error {
		// First run all servers
		dsts := integration.ExtractUniqueDsts(pairs)
		for _, dst := range dsts {
			c, err := integration.StartServer(in, dst)
			if err != nil {
				return err
			}
			defer c.Close()
		}
		// Now start the clients for srcDest pair
		for i, conn := range pairs {
			log.Info(fmt.Sprintf("Test %v: %v -> %v (%v/%v)",
				in.Name(), conn.Src, conn.Dst, i+1, len(pairs)))
			if err := integration.RunClient(in, conn, 1*time.Second); err != nil {
				fmt.Fprintf(os.Stderr, "Error during client execution: %s\n", err)
				return err
			}
		}
		return nil
	})
}
