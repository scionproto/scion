// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/godispatcher/internal/config"
	"github.com/scionproto/scion/go/godispatcher/network"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

var (
	cfg         config.Config
	environment *env.Env
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if returnCode, ok := env.CheckFlags(config.Sample); !ok {
		return returnCode
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("Dispatcher", cfg.Dispatcher.ID)
	defer log.LogPanicAndExit()

	prom.UseDefaultRegWithElem(cfg.Dispatcher.ID)
	ringbuf.InitMetrics("dispatcher", nil)
	go func() {
		defer log.LogPanicAndExit()
		err := RunDispatcher(
			cfg.Dispatcher.DeleteSocket,
			cfg.Dispatcher.ApplicationSocket,
			cfg.Dispatcher.OverlayPort,
		)
		if err != nil {
			fatal.Fatal(err)
		}
	}()
	if cfg.Dispatcher.PerfData != "" {
		go func() {
			err := http.ListenAndServe(cfg.Dispatcher.PerfData, nil)
			if err != nil {
				fatal.Fatal(err)
			}
		}()
	}

	environment = env.SetupEnv(nil)
	cfg.Metrics.StartPrometheus()

	returnCode := waitForTeardown()
	// XXX(scrye): if the dispatcher is shut down on purpose, it is usually
	// done together with the whole stack on top the dispatcher. Cleaning
	// up gracefully does not give us anything in this case. We just clean
	// up the sockets and let the application close.
	errDelete := deleteSocket(cfg.Dispatcher.ApplicationSocket)
	if errDelete != nil {
		log.Warn("Unable to delete socket when shutting down", errDelete)
	}
	switch {
	case returnCode != 0:
		return returnCode
	case errDelete != nil:
		return 1
	default:
		return 0
	}
}

func setupBasic() error {
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return err
	}
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg.InitDefaults()
	env.LogAppStarted("Dispatcher", cfg.Dispatcher.ID)
	return nil
}

func RunDispatcher(deleteSocketFlag bool, applicationSocket string, overlayPort int) error {
	if deleteSocketFlag {
		if err := deleteSocket(cfg.Dispatcher.ApplicationSocket); err != nil {
			return err
		}
	}
	dispatcher := &network.Dispatcher{
		RoutingTable:      network.NewIATable(1024, 65535),
		OverlaySocket:     fmt.Sprintf(":%d", overlayPort),
		ApplicationSocket: applicationSocket,
	}
	log.Debug("Dispatcher starting", "appSocket", applicationSocket, "overlayPort", overlayPort)
	return dispatcher.ListenAndServe()
}

func deleteSocket(socket string) error {
	if _, err := os.Stat(socket); err != nil {
		// File does not exist, or we can't read it, nothing to delete
		return nil
	}
	if err := os.Remove(socket); err != nil {
		return err
	}
	return nil
}

func waitForTeardown() int {
	select {
	case <-environment.AppShutdownSignal:
		return 0
	case <-fatal.Chan():
		return 1
	}
}
