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
	if err := integration.Init("scmp_integration"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	defer log.Flush()

	testCases := []struct {
		Name string
		Args []string
	}{
		{
			"echo_integration",
			[]string{"echo", "-sciondFromIA", "-c", "1", "-timeout", "4s",
				"-local", integration.SrcIAReplace + ",[127.0.0.1]",
				"-remote", integration.DstIAReplace + ",[127.0.0.1]"},
		},
		{
			"traceroute_integration",
			[]string{"tr", "-sciondFromIA", "-timeout", "4s",
				"-local", integration.SrcIAReplace + ",[127.0.0.1]",
				"-remote", integration.DstIAReplace + ",[127.0.0.1]"},
		},
		{
			"recordpath_integration",
			[]string{"rp", "-sciondFromIA", "-timeout", "4s",
				"-local", integration.SrcIAReplace + ",[127.0.0.1]",
				"-remote", integration.DstIAReplace + ",[127.0.0.1]"},
		},
	}

	for _, tc := range testCases {
		log.Info(fmt.Sprintf("Run scmp-%s-tests:", tc.Name))
		in := integration.NewBinaryIntegration(tc.Name, "./bin/scmp", tc.Args, nil,
			integration.NonStdLog)
		if err := runTests(in, integration.IAPairs()); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to run scmp-%s-tests: %s\n", tc.Name, err)
			return 1
		}
	}
	return 0
}

// RunTests runs the scmp tool for each IAPair.
// In case of an error the function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name(), func() error {
		// Run for all srcDest pair
		for i, conn := range pairs {
			log.Info(fmt.Sprintf("Test %v: %v -> %v (%v/%v)",
				in.Name(), conn.Src, conn.Dst, i+1, len(pairs)))
			if err := integration.RunClient(in, conn, integration.DefaultRunTimeout); err != nil {
				fmt.Fprintf(os.Stderr, "Error during client execution: %s\n", err)
				return err
			}
		}
		return nil
	})
}
