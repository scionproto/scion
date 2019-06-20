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
	"github.com/scionproto/scion/go/godispatcher/internal/metrics"
	"github.com/scionproto/scion/go/godispatcher/network"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	cfg config.Config
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if returnCode, ok := env.CheckFlags(&cfg); !ok {
		return returnCode
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("Dispatcher", cfg.Dispatcher.ID)
	defer log.LogPanicAndExit()
	if err := cfg.Validate(); err != nil {
		log.Crit("Unable to validate config", "err", err)
		return 1
	}

	if err := util.CreateParentDirs(cfg.Dispatcher.ApplicationSocket); err != nil {
		log.Crit("Unable to create directory tree for socket", "err", err)
		return 1
	}

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
			defer log.LogPanicAndExit()
			err := http.ListenAndServe(cfg.Dispatcher.PerfData, nil)
			if err != nil {
				fatal.Fatal(err)
			}
		}()
	}

	env.SetupEnv(nil)
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
	cfg.InitDefaults()
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	metrics.Init(cfg.Dispatcher.ID)
	return env.LogAppStarted("Dispatcher", cfg.Dispatcher.ID)
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
	case <-fatal.ShutdownChan():
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}
