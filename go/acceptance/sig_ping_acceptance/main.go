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
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	name    = "sig_ping_acceptance"
	cmd     = "ping"
	iaIPMap = make(map[addr.IA]addr.HostIPv4)
)

func main() {
	os.Exit(realMain())
}

var sigAddr integration.HostAddr = func(ia addr.IA) snet.Addr {
	return snet.Addr{Host: &addr.AppAddr{L3: iaIPMap[ia]}, IA: ia}
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
	if err := readTestingConf(); err != nil {
		log.Crit(fmt.Sprintf("Error reading testing conf: %s", err))
		return 1
	}
	args := []string{cmd, "-c", "4", "-O", integration.DstHostReplace}
	in := integration.NewBinaryIntegration(name, "./integration/bin_wrapper.sh", args, nil)
	err := integration.RunUnaryTests(in, integration.IAPairs(sigAddr),
		integration.DefaultRunTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return 1
	}
	return 0
}

func readTestingConf() error {
	conf := "gen/sig-testing.conf"
	file, err := os.Open(conf)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) == 2 {
			ia, err := addr.IAFromString(parts[0])
			if err != nil {
				return err
			}
			iaIPMap[ia] = addr.HostIPv4(net.ParseIP(parts[1]))
		} else {
			return common.NewBasicError("Bad line format", nil, "line", line)
		}
	}
	return nil
}
