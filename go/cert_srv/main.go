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
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/cert_srv/internal/reiss"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
)

var (
	cfg         config.Config
	state       *config.State
	reissRunner *periodic.Runner
	discRunners idiscovery.Runners
	corePusher  *periodic.Runner
	msgr        infra.Messenger
	trustDB     trustdb.TrustDB
)

func init() {
	flag.Usage = env.Usage
}

// main initializes the certificate server and starts the dispatcher.
func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(&cfg); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped(common.CS, cfg.General.ID)
	defer log.LogPanicAndExit()
	// Setup the state and the messenger
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	// Start the periodic reissuance task.
	startReissRunner()
	// Start the periodic fetching from discovery service.
	startDiscovery()
	// Start the messenger.
	go func() {
		defer log.LogPanicAndExit()
		msgr.ListenAndServe()
	}()
	// Set environment to listen for signals.
	infraenv.InitInfraEnvironmentFunc(cfg.General.Topology, func() {
		if err := reload(); err != nil {
			log.Error("Unable to reload", "err", err)
		}
	})
	// Cleanup when the CS exits.
	defer stop()
	cfg.Metrics.StartPrometheus()
	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

// reload reloads the topology and CS config.
func reload() error {
	// FIXME(roosd): KeyConf reloading is not yet supported.
	// https://github.com/scionproto/scion/issues/2077
	var newConf config.Config
	// Load new config to get the CS parameters.
	if _, err := toml.DecodeFile(env.ConfigFile(), &newConf); err != nil {
		return err
	}
	newConf.InitDefaults()
	if err := newConf.Validate(); err != nil {
		return common.NewBasicError("Unable to validate new config", err)
	}
	cfg.CS = newConf.CS
	// Restart the periodic reissue task to respect the fresh parameters.
	stopReissRunner()
	startReissRunner()
	return nil
}

// startReissRunner starts a periodic reissuance task. Core starts self-issuer.
// Non-core starts a requester.
func startReissRunner() {
	corePusher = periodic.StartPeriodicTask(
		&reiss.CorePusher{
			LocalIA: itopo.Get().ISD_AS,
			TrustDB: state.TrustDB,
			Msger:   msgr,
		},
		periodic.NewTicker(time.Hour),
		time.Minute,
	)
	corePusher.TriggerRun()
	if !cfg.CS.AutomaticRenewal {
		log.Info("Reissue disabled, not starting reiss task.")
		return
	}
	if itopo.Get().Core {
		log.Info("Starting periodic reiss.Self task")
		reissRunner = periodic.StartPeriodicTask(
			&reiss.Self{
				Msgr:       msgr,
				State:      state,
				IA:         itopo.Get().ISD_AS,
				IssTime:    cfg.CS.IssuerReissueLeadTime.Duration,
				LeafTime:   cfg.CS.LeafReissueLeadTime.Duration,
				CorePusher: corePusher,
			},
			periodic.NewTicker(cfg.CS.ReissueRate.Duration),
			cfg.CS.ReissueTimeout.Duration,
		)
		return
	}
	log.Info("Starting periodic reiss.Requester task")
	reissRunner = periodic.StartPeriodicTask(
		&reiss.Requester{
			Msgr:       msgr,
			State:      state,
			IA:         itopo.Get().ISD_AS,
			LeafTime:   cfg.CS.LeafReissueLeadTime.Duration,
			CorePusher: corePusher,
		},
		periodic.NewTicker(cfg.CS.ReissueRate.Duration),
		cfg.CS.ReissueTimeout.Duration,
	)
}

func startDiscovery() {
	var err error
	discRunners, err = idiscovery.StartRunners(cfg.Discovery, discovery.Full,
		idiscovery.TopoHandlers{}, nil)
	if err != nil {
		fatal.Fatal(common.NewBasicError("Unable to start dynamic topology fetcher", err))
	}
}

func stopReissRunner() {
	if corePusher != nil {
		corePusher.Kill()
	}
	if reissRunner != nil {
		reissRunner.Stop()
	}
}

func stop() {
	stopReissRunner()
	discRunners.Kill()
	msgr.CloseServer()
	trustDB.Close()
}
