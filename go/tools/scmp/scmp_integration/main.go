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

	cmnArgs := []string{"-sciondFromIA", "-timeout", "4s", "-local", integration.SrcAddrPattern,
		"-remote", integration.DstAddrPattern}

	testCases := []struct {
		Name string
		Args []string
	}{
		{
			"echo_integration",
			append([]string{"echo", "-c", "1"}, cmnArgs...),
		},
		{
			"traceroute_integration",
			append([]string{"tr"}, cmnArgs...),
		},
		{
			"recordpath_integration",
			append([]string{"rp"}, cmnArgs...),
		},
	}

	for _, tc := range testCases {
		log.Info(fmt.Sprintf("Run scmp-%s-tests:", tc.Name))
		in := integration.NewBinaryIntegration(tc.Name, "./integration/bin_wrapper.sh",
			append([]string{"./bin/scmp"}, tc.Args...), nil)
		err := integration.RunUnaryTests(in, integration.IAPairs(integration.DispAddr),
			integration.DefaultRunTimeout)
		if err != nil {
			log.Error(fmt.Sprintf("Error during scmp-%s-tests", tc.Name), "err", err)
			return 1
		}
	}
	return 0
}
