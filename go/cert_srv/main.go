// Copyright 2017 ETH Zurich
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
	_ "net/http/pprof"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/cert_srv/internal/csconfig"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
)

type Config struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	Trust   env.Trust
	Infra   env.Infra
	CS      *csconfig.Conf
}

type task interface {
	Run()
	Stop()
}

var (
	config      *Config
	environment *env.Env
	flagConfig  = flag.String("config", "", "Service TOML config file (required)")

	reissTask task
	currMsgr  *messenger.Messenger
)

// main initializes the certificate server and starts the dispatcher.
func main() {
	os.Exit(realMain())
}

func realMain() int {
	flag.Parse()
	if *flagConfig == "" {
		fmt.Fprintln(os.Stderr, "Missing config file")
		flag.Usage()
		return 1
	}
	if err := setup(*flagConfig); err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		return 1
	}
	defer log.LogPanicAndExit()
	defer stop()
	// Create a channel where prometheus can signal fatal errors
	fatalC := make(chan error, 1)
	config.Metrics.StartPrometheus(fatalC)
	select {
	case <-environment.AppShutdownSignal:
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		return 0
	case err := <-fatalC:
		// Prometheus encountered a fatal error, thus we exit.
		log.Crit("Unable to listen and serve", "err", err)
		return 1
	}
}

func setup(configName string) error {
	config = &Config{}
	if _, err := toml.DecodeFile(configName, config); err != nil {
		return err
	}
	if err := env.InitGeneral(&config.General); err != nil {
		return err
	}
	itopo.SetCurrentTopology(config.General.Topology)
	if err := env.InitLogging(&config.Logging); err != nil {
		return err
	}
	if err := setConfig(config, nil); err != nil {
		return err
	}
	// TODO(roosd): add reload function.
	environment = env.SetupEnv(nil)
	return nil
}

func stop() {
	reissTask.Stop()
	currMsgr.CloseServer()
}
