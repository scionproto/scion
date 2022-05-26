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
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app/feature"
	"github.com/scionproto/scion/tools/integration"
)

var (
	subset      string
	attempts    int
	timeout     = &util.DurWrap{Duration: 10 * time.Second}
	parallelism int
	name        string
	cmd         string
	features    string
	epic        bool
)

func getCmd() (string, bool) {
	return cmd, strings.Contains(cmd, "end2end")
}

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

	clientArgs := []string{
		"-log.console", "debug",
		"-attempts", strconv.Itoa(attempts),
		"-timeout", timeout.String(),
		"-local", integration.SrcAddrPattern + ":0",
		"-remote", integration.DstAddrPattern + ":" + integration.ServerPortReplace,
		fmt.Sprintf("-epic=%t", epic),
	}
	serverArgs := []string{
		"-mode", "server",
		"-local", integration.DstAddrPattern + ":0",
	}
	if len(features) != 0 {
		clientArgs = append(clientArgs, "--features", features)
		serverArgs = append(serverArgs, "--features", features)
	}
	if !*integration.Docker {
		clientArgs = append(clientArgs, "-sciond", integration.Daemon)
		serverArgs = append(serverArgs, "-sciond", integration.Daemon)
	}

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
	flag.StringVar(&cmd, "cmd", "./bin/end2end",
		"The end2end binary to run (default: ./bin/end2end)")
	flag.StringVar(&name, "name", "end2end_integration",
		"The name of the test that is running (default: end2end_integration)")
	flag.Var(timeout, "timeout", "The timeout for each attempt")
	flag.StringVar(&subset, "subset", "all", "Subset of pairs to run (all|core#core|"+
		"noncore#localcore|noncore#core|noncore#noncore)")
	flag.IntVar(&parallelism, "parallelism", 1, "How many end2end tests run in parallel.")
	flag.StringVar(&features, "features", "",
		fmt.Sprintf("enable development features (%v)", feature.String(&feature.Default{}, "|")))
	flag.BoolVar(&epic, "epic", false, "Enable EPIC.")
}

// runTests runs the end2end tests for all pairs. In case of an error the
// function is terminated immediately.
func runTests(in integration.Integration, pairs []integration.IAPair) error {
	return integration.ExecuteTimed(in.Name(), func() error {
		// Make sure that all executed commands can write to the RPC server
		// after shutdown.
		defer time.Sleep(time.Second)

		// Estimating the timeout we should have is hard. CI will abort after 10
		// minutes anyway. Thus this value.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		// First run all servers
		type srvResult struct {
			cleaner func()
			err     error
		}
		// Start servers in parallel.
		srvResults := make(chan srvResult)
		for _, dst := range integration.ExtractUniqueDsts(pairs) {
			go func(dst *snet.UDPAddr) {
				defer log.HandlePanic()

				srvCtx, cancel := context.WithCancel(ctx)
				waiter, err := in.StartServer(srvCtx, dst)
				if err != nil {
					log.Error(fmt.Sprintf("Error in server: %s", dst.String()), "err", err)
				}
				cleaner := func() {
					cancel()
					if waiter != nil {
						waiter.Wait()
					}
				}
				srvResults <- srvResult{cleaner: cleaner, err: err}
			}(dst)
		}
		// Wait for all servers being started.
		var errs serrors.List
		for range integration.ExtractUniqueDsts(pairs) {
			res := <-srvResults
			// We need to register a cleanup for all servers.
			// Do not short-cut exit here.
			if res.err != nil {
				errs = append(errs, res.err)
			}
			defer res.cleaner()
		}
		if err := errs.ToError(); err != nil {
			return err
		}

		// Start a done signal listener. This is how the end2end binary
		// communicates with this integration test. This is solely used to print
		// the progress of the test.
		var ctrMtx sync.Mutex
		var ctr int
		doneDir, err := filepath.Abs(filepath.Join(integration.LogDir(), "socks"))
		if err != nil {
			return serrors.WrapStr("determining abs path", err)
		}
		if err := os.MkdirAll(doneDir, os.ModePerm); err != nil {
			return serrors.WrapStr("creating socks directory", err)
		}
		// this is a bit of a hack, socket file names have a max length of 108
		// and inside bazel tests we easily have longer paths, therefore we
		// create a temporary symlink to the directory where we put the socket
		// file.
		tmpDir, err := os.MkdirTemp("", "e2e_integration")
		if err != nil {
			return serrors.WrapStr("creating temp dir", err)
		}
		if err := os.Remove(tmpDir); err != nil {
			return serrors.WrapStr("deleting temp dir", err)
		}
		if err := os.Symlink(doneDir, tmpDir); err != nil {
			return serrors.WrapStr("symlinking socks dir", err)
		}
		doneDir = tmpDir
		defer os.Remove(doneDir)
		socket, clean, err := integration.ListenDone(doneDir, func(src, dst addr.IA) {
			ctrMtx.Lock()
			defer ctrMtx.Unlock()
			ctr++
			testInfo := fmt.Sprintf("%v -> %v (%v/%v)", src, dst, ctr, len(pairs))
			log.Info(fmt.Sprintf("Test %v: %s", in.Name(), testInfo))
		})
		if err != nil {
			return serrors.WrapStr("creating done listener", err)
		}
		defer clean()

		if *integration.Docker {
			socket = strings.Replace(socket, doneDir, "/share/logs/socks", -1)
		}

		// CI collapses if parallelism is too high.
		semaphore := make(chan struct{}, parallelism)

		// Docker exec comes with a 1 second overhead. We group all the pairs by
		// the clients. And run all pairs for a given client in one execution.
		// Thus, reducing the overhead dramatically.
		groups := integration.GroupBySource(pairs)
		clientResults := make(chan error, len(groups))
		for src, dsts := range groups {
			go func(src *snet.UDPAddr, dsts []*snet.UDPAddr) {
				defer log.HandlePanic()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				// Aggregate all the commands that need to be run.
				cmds := make([]integration.Cmd, 0, len(dsts))
				for _, dst := range dsts {
					cmd, err := clientTemplate(socket).Template(src, dst)
					if err != nil {
						clientResults <- err
						return
					}
					cmds = append(cmds, cmd)
				}
				var tester string
				if *integration.Docker {
					tester = integration.TesterID(src)
				}
				logFile := fmt.Sprintf("%s/client_%s.log",
					logDir(),
					addr.FormatIA(src.IA, addr.WithFileSeparator()),
				)
				err := integration.Run(ctx, integration.RunConfig{
					Commands: cmds,
					LogFile:  logFile,
					Tester:   tester,
				})
				if err != nil {
					err = serrors.WithCtx(err, "file", relFile(logFile))
				}
				clientResults <- err
			}(src, dsts)
		}
		errs = nil
		for range groups {
			err := <-clientResults
			if err != nil {
				errs = append(errs, err)
			}
		}
		return errs.ToError()
	})
}

func clientTemplate(progressSock string) integration.Cmd {
	bin, progress := getCmd()
	cmd := integration.Cmd{
		Binary: bin,
		Args: []string{
			"-log.console", "debug",
			"-attempts", strconv.Itoa(attempts),
			"-timeout", timeout.String(),
			"-local", integration.SrcAddrPattern + ":0",
			"-remote", integration.DstAddrPattern + ":" + integration.ServerPortReplace,
			fmt.Sprintf("-epic=%t", epic),
		},
	}
	if len(features) != 0 {
		cmd.Args = append(cmd.Args, "--features", features)
	}
	if progress {
		cmd.Args = append(cmd.Args, "-progress", progressSock)
	}
	if !*integration.Docker {
		cmd.Args = append(cmd.Args, "-sciond", integration.Daemon)
	}
	return cmd
}

// getPairs returns the pairs to test according to the specified subset.
func getPairs() ([]integration.IAPair, error) {
	pairs := integration.IAPairs(integration.DispAddr)
	if subset == "all" {
		return pairs, nil
	}
	parts := strings.Split(subset, "#")
	if len(parts) != 2 {
		return nil, serrors.New("Invalid subset", "subset", subset)
	}
	return filter(parts[0], parts[1], pairs, integration.ASList), nil
}

// filter returns the list of ASes that are part of the desired subset.
func filter(src, dst string, pairs []integration.IAPair, ases *util.ASList) []integration.IAPair {
	var res []integration.IAPair
	s, err1 := addr.ParseIA(src)
	d, err2 := addr.ParseIA(dst)
	if err1 == nil && err2 == nil {
		for _, pair := range pairs {
			if pair.Src.IA.Equal(s) && pair.Dst.IA.Equal(d) {
				res = append(res, pair)
				return res
			}
		}
	}
	for _, pair := range pairs {
		filter := !contains(ases, src != "noncore", pair.Src.IA)
		filter = filter || !contains(ases, dst != "noncore", pair.Dst.IA)
		if dst == "localcore" {
			filter = filter || pair.Src.IA.ISD() != pair.Dst.IA.ISD()
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

func logDir() string {
	return filepath.Join(integration.LogDir(), name)
}

func relFile(file string) string {
	rel, err := filepath.Rel(filepath.Dir(integration.LogDir()), file)
	if err != nil {
		return file
	}
	return rel
}
