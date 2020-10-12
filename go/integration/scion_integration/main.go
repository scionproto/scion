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
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/pkg/app/feature"
)

var features string

func main() {
	os.Exit(realMain())
}

func realMain() int {
	addFlags()
	if err := integration.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.HandlePanic()
	defer log.Flush()
	if len(features) != 0 {
		if _, err := feature.ParseDefault(strings.Split(features, ",")); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing features: %s\n", err)
			return 1
		}
	}

	cmnArgs := []string{
		"--timeout", "4s",
		"--sciond", integration.SCIOND,
	}
	if *integration.Docker {
		cmnArgs = append(cmnArgs,
			"--local", integration.SrcHostReplace,
		)
	}
	cmnArgs = append(cmnArgs, integration.DstAddrPattern)
	if len(features) != 0 {
		cmnArgs = append(cmnArgs, "--features", features)
	}

	testCases := []struct {
		Name  string
		Args  []string
		Pairs func(integration.HostAddr) []integration.IAPair
	}{
		{
			Name:  "ping",
			Args:  append([]string{"./bin/scion", "ping", "-c", "1"}, cmnArgs...),
			Pairs: integration.IAPairs,
		},
		{
			Name:  "traceroute",
			Args:  append([]string{"./bin/scion", "traceroute"}, cmnArgs...),
			Pairs: integration.UniqueIAPairs,
		},
	}

	for _, tc := range testCases {
		log.Info(fmt.Sprintf("Run scion %s tests:", tc.Name))
		in := integration.NewBinaryIntegration(tc.Name, integration.WrapperCmd, tc.Args, nil)
		pairs := tc.Pairs(integration.DispAddr)
		if err := integration.RunUnaryTests(in, pairs, integration.DefaultRunTimeout); err != nil {
			log.Error(fmt.Sprintf("Error during scion %s tests", tc.Name), "err", err)
			return 1
		}
	}
	return 0
}

func addFlags() {
	flag.StringVar(&features, "features", "",
		fmt.Sprintf("enable development features (%v)", feature.String(&feature.Default{}, "|")))
}
