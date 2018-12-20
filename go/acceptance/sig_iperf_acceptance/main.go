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
//
// The sig_iperf acceptance test checks whether the SIG sustains a certain load. It performs TCP
// and UDP performance tests using a modern version of iperf3. For UDP different combinations of
// bandwidths and packet sizes are used.
// Note: This is not a general performance test, it only checks for minimal (acceptance)
// performance.

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/scionproto/scion/go/acceptance"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	name = "sig_iperf_acceptance"
	cmd  = "iperf3"
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
	if !*integration.Docker {
		log.Crit(fmt.Sprintf("Can only run %s test with docker!", name))
		return 1
	}
	if err := acceptance.ReadTestingConf(); err != nil {
		log.Crit(fmt.Sprintf("Error reading testing conf: %s", err))
		return 1
	}
	testCases := []struct {
		Name       string
		ClientArgs []string
	}{
		{
			name + "_udp_10Mbps_80B",
			[]string{"-u", "--bandwidth", "10M", "--length", "80"},
		},
		{
			name + "_udp_25Mbps_512B",
			[]string{"-u", "--bandwidth", "25M", "--length", "512"},
		},
		{
			name + "_udp_50Mbps_1460B",
			[]string{"-u", "--bandwidth", "50M", "--length", "1460"},
		},
	}
	cmnArgs := []string{integration.WrapperCmd, cmd, "-p", "12000", "--verbose", "--forceflush"}
	serverArgs := append(cmnArgs, "-s", "--one-off")
	for _, tc := range testCases {
		log.Info(fmt.Sprintf("Run iperf-%s-tests:", tc.Name))
		clientArgs := append(cmnArgs, []string{"-c", integration.DstHostReplace, "--time", "5"}...)
		clientArgs = append(clientArgs, tc.ClientArgs...)
		cmd := "IA=" + integration.DstIAReplace
		in := integration.NewBinaryIntegration(tc.Name, cmd, clientArgs, serverArgs)
		if err := integration.RunBinaryTests(in,
			integration.UniqueIAPairs(acceptance.SigAddr), 30*time.Second); err != nil {
			log.Error(fmt.Sprintf("Error during iperf-%s-tests", tc.Name), "err", err)
			return 1
		}
	}
	return 0
}
