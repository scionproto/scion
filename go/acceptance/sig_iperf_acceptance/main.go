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
			name + "_tcp",
			[]string{},
		},
		{
			name + "_udp_100Mbps",
			[]string{"-u", "-b", "100M"},
		},
		{
			name + "_udp_150Mbps",
			[]string{"-u", "-b", "150M"},
		},
		{
			name + "_udp_200Mbps",
			[]string{"-u", "-b", "200M"},
		},
		{
			name + "_udp_250Mbps",
			[]string{"-u", "-b", "250M"},
		},
	}
	cmnArgs := []string{integration.WrapperCmd, cmd, "-p", "12000", "--verbose"}
	serverArgs := append(cmnArgs, "-s", "--one-off")
	for _, tc := range testCases {
		log.Info(fmt.Sprintf("Run iperf-%s-tests:", tc.Name))
		clientArgs := append(cmnArgs, []string{"-c", integration.DstHostReplace}...)
		clientArgs = append(clientArgs, tc.ClientArgs...)
		cmd := "IA=" + integration.DstIAReplace
		in := integration.NewBinaryIntegration(tc.Name, cmd, clientArgs,
			serverArgs)
		if err := runTests(in, integration.UniqueIAPairs(acceptance.SigAddr)); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to run iperf-%s-tests: %s\n", tc.Name, err)
			return 1
		}
	}
	return 0
}

// RunTests runs the client and server for each IAPair.
// In case of an error the function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name(), func() error {
		for i, conn := range pairs {
			// Start the server for srcDest pair
			s, err := integration.StartServer(in, conn.Dst)
			if err != nil {
				return err
			}
			defer s.Close()
			// Now start the client
			log.Info(fmt.Sprintf("Test %v: %v -> %v (%v/%v)",
				in.Name(), conn.Src.IA, conn.Dst.IA, i+1, len(pairs)))
			t := 30 * time.Second
			if err := integration.RunClient(in, conn, t); err != nil {
				log.Error("Error during client execution", "err", err)
				return err
			}
		}
		return nil
	})
}
