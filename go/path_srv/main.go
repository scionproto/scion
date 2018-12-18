// Copyright 2018 Anapaya Systems
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
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/path_srv/internal/handlers"
	"github.com/scionproto/scion/go/path_srv/internal/psconfig"
	"github.com/scionproto/scion/go/path_srv/internal/segsyncer"
	"github.com/scionproto/scion/go/proto"
)

type Config struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	TrustDB truststorage.TrustDBConf
	Infra   env.Infra
	PS      psconfig.Config
}

var (
	config      Config
	environment *env.Env

	tasks *periodicTasks
)

func init() {
	flag.Usage = env.Usage
}

// main initializes the path server and starts the dispatcher.
func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(psconfig.Sample); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped(common.PS, config.General.ID)
	defer log.LogPanicAndExit()
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	pathDB, revCache, err := pathstorage.NewPathStorage(config.PS.PathDB, config.PS.RevCache)
	if err != nil {
		log.Crit("Unable to initialize path storage", "err", err)
		return 1
	}
	trustDB, err := config.TrustDB.New()
	if err != nil {
		log.Crit("Unable to initialize trustDB", "err", err)
		return 1
	}
	topo := itopo.GetCurrentTopology()
	trustConf := &trust.Config{
		ServiceType: proto.ServiceType_ps,
	}
	trustStore, err := trust.NewStore(trustDB, topo.ISD_AS, trustConf, log.Root())
	if err != nil {
		log.Crit("Unable to initialize trust store", "err", err)
		return 1
	}
	err = trustStore.LoadAuthoritativeTRC(filepath.Join(config.General.ConfigDir, "certs"))
	if err != nil {
		log.Crit("TRC error", "err", err)
		return 1
	}
	topoAddress := topo.PS.GetById(config.General.ID)
	if topoAddress == nil {
		log.Crit("Unable to find topo address")
		return 1
	}
	msger, err := infraenv.InitMessenger(
		topo.ISD_AS,
		env.GetPublicSnetAddress(topo.ISD_AS, topoAddress),
		env.GetBindSnetAddress(topo.ISD_AS, topoAddress),
		addr.SvcPS,
		config.General.ReconnectToDispatcher,
		trustStore,
	)
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger, "err", err)
		return 1
	}
	msger.AddHandler(infra.ChainRequest, trustStore.NewChainReqHandler(false))
	// TODO(lukedirtwalker): with the new CP-PKI design the PS should no longer need to handle TRC
	// and cert requests.
	msger.AddHandler(infra.TRCRequest, trustStore.NewTRCReqHandler(false))
	args := handlers.HandlerArgs{
		PathDB:     pathDB,
		RevCache:   revCache,
		TrustStore: trustStore,
		Config:     config.PS,
		IA:         topo.ISD_AS,
	}
	core := topo.Core
	var segReqHandler infra.Handler
	deduper := handlers.NewGetSegsDeduper(msger)
	if core {
		segReqHandler = handlers.NewSegReqCoreHandler(args, deduper)
	} else {
		segReqHandler = handlers.NewSegReqNonCoreHandler(args, deduper)
	}
	msger.AddHandler(infra.SegRequest, segReqHandler)
	msger.AddHandler(infra.SegReg, handlers.NewSegRegHandler(args))
	msger.AddHandler(infra.IfStateInfos, handlers.NewIfStatInfoHandler(args))
	if config.PS.SegSync && core {
		// Old down segment sync mechanism
		msger.AddHandler(infra.SegSync, handlers.NewSyncHandler(args))
	}
	msger.AddHandler(infra.SegRev, handlers.NewRevocHandler(args))
	config.Metrics.StartPrometheus()
	// Start handling requests/messages
	go func() {
		defer log.LogPanicAndExit()
		msger.ListenAndServe()
	}()
	tasks = &periodicTasks{
		args:    args,
		msger:   msger,
		trustDB: trustDB,
	}
	tasks.Start()
	defer tasks.Kill()
	select {
	case <-environment.AppShutdownSignal:
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		return 0
	case <-fatal.Chan():
		return 1
	}
}

type periodicTasks struct {
	args          handlers.HandlerArgs
	msger         infra.Messenger
	trustDB       trustdb.TrustDB
	mtx           sync.Mutex
	running       bool
	segSyncers    []*periodic.Runner
	pathDBCleaner *periodic.Runner
	cryptosyncer  *periodic.Runner
	rcCleaner     *periodic.Runner
}

func (t *periodicTasks) Start() {
	fatal.Check()
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.running {
		log.Warn("Trying to start task, but they are running! Ignored.")
		return
	}
	var err error
	if config.PS.SegSync && config.General.Topology.Core {
		t.segSyncers, err = segsyncer.StartAll(t.args, t.msger)
		if err != nil {
			fatal.Fatal(common.NewBasicError("Unable to start seg syncer", err))
		}
	}
	t.pathDBCleaner = periodic.StartPeriodicTask(pathdb.NewCleaner(t.args.PathDB),
		periodic.NewTicker(300*time.Second), 295*time.Second)
	t.rcCleaner = periodic.StartPeriodicTask(revcache.NewCleaner(t.args.RevCache),
		periodic.NewTicker(10*time.Second), 10*time.Second)
	t.running = true
}

func (t *periodicTasks) Kill() {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if !t.running {
		log.Warn("Trying to stop tasks, but they are not running! Ignored.")
		return
	}
	for i := range t.segSyncers {
		syncer := t.segSyncers[i]
		syncer.Kill()
	}
	t.pathDBCleaner.Kill()
	t.rcCleaner.Kill()
	t.running = false
}

func setupBasic() error {
	if _, err := toml.DecodeFile(env.ConfigFile(), &config); err != nil {
		return err
	}
	if err := env.InitLogging(&config.Logging); err != nil {
		return err
	}
	return env.LogAppStarted(common.PS, config.General.ID)
}

func setup() error {
	if err := env.InitGeneral(&config.General); err != nil {
		return err
	}
	itopo.SetCurrentTopology(config.General.Topology)
	environment = infraenv.InitInfraEnvironment(config.General.TopologyPath)
	config.PS.InitDefaults()
	return nil
}
