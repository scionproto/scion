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
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	name = "ping_sig_integration"
	cmd  = "ping"
)

func main() {
	os.Exit(realMain())
}

var sigAddr integration.HostAddr = func(ia addr.IA) snet.Addr {
	conf := "gen/sig-testing.conf"
	file, err := os.Open(conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read from %s: %s\n", conf, err)
		os.Exit(1)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var ip addr.HostIPv4
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) == 2 && parts[0] == ia.String() {
			ip = addr.HostIPv4(net.ParseIP(parts[1]))
		}
	}
	if ip == nil {
		fmt.Fprintf(os.Stderr, "Unable to read IP for %s!\n", ia.String())
		os.Exit(1)
	}
	return snet.Addr{Host: &addr.AppAddr{L3: ip}, IA: ia}
}

func realMain() int {
	if err := integration.Init(name); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	if !*integration.Docker {
		fmt.Fprintf(os.Stderr, "Can only run %s test with docker!\n", name)
		return 1
	}
	defer log.LogPanicAndExit()
	defer log.Flush()
	clientArgs := []string{"-c", "4", integration.DstHostReplace, "1>&2"}
	in := integration.NewBinaryIntegration(name, cmd, clientArgs, []string{},
		integration.NonStdLog)
	if err := runTests(in, integration.IAPairs(sigAddr)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run tests: %s\n", err)
		return 1
	}
	return 0
}

// RunTests runs the client for each IAPair.
// In case of an error the function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name(), func() error {
		// Start the clients for srcDest pair
		for i, conn := range pairs {
			log.Info(fmt.Sprintf("Test %v: %v,%v -> %v,%v (%v/%v)", in.Name(), conn.Src.IA,
				conn.Src.Host, conn.Dst.IA, conn.Dst.Host, i+1, len(pairs)))
			// log.Debug(fmt.Sprintf("Ping %s from %s", conn.Dst.Host.L3, conn.Src.Host.L3))
			if err := integration.RunClient(in, conn, integration.DefaultRunTimeout); err != nil {
				log.Error("Error during client execution", "err", err)
				return err
			}
		}
		return nil
	})
}
