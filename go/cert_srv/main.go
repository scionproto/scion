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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
)

type Config struct {
	General env.General
	Sciond  env.SciondClient `toml:"sd_client"`
	Logging env.Logging
	Metrics env.Metrics
	Trust   env.Trust
	Infra   env.Infra
	CS      csconfig.Conf
	state   *csconfig.State
}

var (
	config      Config
	environment *env.Env
	reissRunner *periodic.Runner
	currMsgr    *messenger.Messenger
)

func init() {
	flag.Usage = env.Usage
}

// main initializes the certificate server and starts the dispatcher.
func main() {
	os.Exit(realMain())
}

func realMain() int {
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(csconfig.Sample); !ok {
		return v
	}
	if err := setup(env.ConfigFile()); err != nil {
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
	if _, err := toml.DecodeFile(configName, &config); err != nil {
		return err
	}
	if err := env.InitGeneral(&config.General); err != nil {
		return err
	}
	itopo.SetCurrentTopology(config.General.Topology)
	if err := env.InitLogging(&config.Logging); err != nil {
		return err
	}
	if err := initConfig(&config); err != nil {
		return err
	}
	environment = infraenv.InitInfraEnvironmentFunc(config.General.TopologyPath, func() {
		if err := reload(configName); err != nil {
			log.Error("Unable to reload", "err", err)
		}
	})
	return nil
}

func reload(configName string) error {
	// FIXME(roosd): KeyConf reloading is not yet supported.
	config.General.Topology = itopo.GetCurrentTopology()
	var newConf Config
	// Load new config to get the CS parameters.
	if _, err := toml.DecodeFile(configName, &newConf); err != nil {
		return err
	}
	if err := newConf.CS.Init(config.General.ConfigDir); err != nil {
		return common.NewBasicError("Unable to initialize CS config", err)
	}
	config.CS = newConf.CS
	reissRunner.Stop()
	reissRunner = startReissRunner(&config, currMsgr)
	return nil
}

func stop() {
	reissRunner.Stop()
	currMsgr.CloseServer()
}
