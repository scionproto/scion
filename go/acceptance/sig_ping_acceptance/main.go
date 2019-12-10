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
// The sig_ping acceptance test checks for basic connectivity between AS through the SIG, using
// standard ping.

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/acceptance"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	name     = "sig_ping_acceptance"
	cmd      = "ping"
	attempts = flag.Int("attempts", 5, "Number of ping attempts.")
	fail     = flag.Bool("fail", false, "Succeed if the pings don't make it through.")
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
	args := []string{cmd, "-c", strconv.Itoa(*attempts), "-O", integration.DstHostReplace}
	in := integration.NewBinaryIntegration(name, integration.WrapperCmd, args, nil)
	err := integration.RunUnaryTests(in, integration.UniqueIAPairs(acceptance.SigAddr),
		time.Duration(*attempts)*time.Second+integration.DefaultRunTimeout)
	if !*fail && err != nil {
		// The pings were supposed to get through but they didn't.
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return 1

	}
	if *fail && err == nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: "+
			"Pings were supposed to not to reach the destination but they did.\n")
		return 1

	}
	return 0
}
