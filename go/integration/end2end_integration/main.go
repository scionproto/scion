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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	name = "end2end_integration"
	cmd  = "./bin/end2end"
)

var (
	subset   string
	attempts int
	runAll   bool
	timeout  = &util.DurWrap{Duration: 5 * time.Second}
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	addFlags()
	if err := integration.Init(name); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init: %s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	defer log.Flush()
	clientArgs := []string{"-log.console", "debug", "-attempts", strconv.Itoa(attempts),
		"-timeout", timeout.String(),
		"-local", integration.SrcAddrPattern + ":0",
		"-remote", integration.DstAddrPattern + ":" + integration.ServerPortReplace}
	serverArgs := []string{"-log.console", "debug", "-mode", "server",
		"-local", integration.DstAddrPattern + ":0"}
	in := integration.NewBinaryIntegration(name, cmd, clientArgs, serverArgs)
	pairs, err := getPairs()
	if err != nil {
		log.Error("Error selecting tests", "err", err)
		return 1
	}
	if err := runTests(in, pairs); err != nil {
		log.Error("Error during tests", "err", err)
		return 1
	}
	return 0
}

// addFlags adds the necessary flags.
func addFlags() {
	flag.IntVar(&attempts, "attempts", 1, "Number of attempts per client before giving up.")
	flag.BoolVar(&runAll, "all", false, "Run all tests, instead of exiting on first error.")
	flag.Var(timeout, "timeout", "The timeout for each attempt")
	flag.StringVar(&subset, "subset", "all", "Subset of pairs to run (all|core-core|"+
		"noncore-localcore|noncore-core|noncore-noncore)")
}

// runTests runs the end2end tests for all pairs. In case of an error the
// function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name(), func() error {
		// First run all servers
		var wgs sync.WaitGroup
		for _, dst := range integration.ExtractUniqueDsts(pairs) {
			wgs.Add(1)
			go func(d *snet.UDPAddr) {
				defer wgs.Done()
				s, err := integration.StartServer(in, d)
				if err != nil {
					log.Error(fmt.Sprintf("Error in server: %s", d.String()), "err", err)
					return
				}
				log.Info(fmt.Sprintf("server: %s up", d.String()))
				defer s.Close() //TODO(karampok). this is not working when docker
			}(dst)
		}
		wgs.Wait()

		timeout := integration.DefaultRunTimeout + timeout.Duration*time.Duration(attempts)
		var lastErr error

		locks := make(chan struct{}, 20)
		for i := 0; i < 20; i++ {
			locks <- struct{}{}
		}

		var wgc sync.WaitGroup
		for i, conn := range pairs {
			wgc.Add(1)
			testInfo := fmt.Sprintf("%v -> %v (%v/%v)", conn.Src.IA, conn.Dst.IA, i+1, len(pairs))
			go func(info string, p integration.IAPair) {
				<-locks
				defer func() {
					locks <- struct{}{}
				}()
				defer wgc.Done()
				log.Info(fmt.Sprintf("Test %v: %s", in.Name(), testInfo))
				if err := integration.RunClient(in, p, timeout); err != nil {
					log.Error(fmt.Sprintf("Error in client: %s", testInfo), "err", err)
					lastErr = err
					return
				}
				log.Info(fmt.Sprintf("Test %v: %s ok", in.Name(), testInfo))
			}(testInfo, conn)
		}

		wgc.Wait()
		return lastErr
	})
}

// getPairs returns the pairs to test according to the specified subset.
func getPairs() ([]integration.IAPair, error) {
	pairs := integration.IAPairs(integration.DispAddr)
	if subset == "all" {
		return pairs, nil
	}
	ases, err := util.LoadASList("gen/as_list.yml")
	if err != nil {
		return nil, err
	}
	parts := strings.Split(subset, "-")
	if len(parts) != 2 {
		return nil, common.NewBasicError("Invalid subset", nil, "subset", subset)
	}
	return filter(parts[0], parts[1], pairs, ases), nil
}

// filter returns the list of ASes that are part of the desired subset.
func filter(src, dst string, pairs []integration.IAPair, ases *util.ASList) []integration.IAPair {
	var res []integration.IAPair
	for _, pair := range pairs {
		filter := !contains(ases, src != "noncore", pair.Src.IA)
		filter = filter || !contains(ases, dst != "noncore", pair.Dst.IA)
		if dst == "localcore" {
			filter = filter || pair.Src.IA.I != pair.Dst.IA.I
		}
		if !filter {
			res = append(res, pair)
		}
	}
	return res
}

func contains(ases *util.ASList, core bool, ia addr.IA) bool {
	l := ases.Core
	if !core {
		l = ases.NonCore
	}
	for _, as := range l {
		if ia.Equal(as) {
			return true
		}
	}
	return false
}
