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
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	pathdbbe "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/path_srv/internal/cleaner"
	"github.com/scionproto/scion/go/path_srv/internal/handlers"
	"github.com/scionproto/scion/go/path_srv/internal/periodic"
)

type Config struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	Trust   env.Trust
	Infra   env.Infra
	PS      struct {
		// SegSync enables the "old" replication of down segments between cores,
		// using SegSync messages.
		SegSync bool
		PathDB  string
	}
}

var (
	config      Config
	environment *env.Env
	flagConfig  = flag.String("config", "", "Service TOML config file (required)")
)

// main initializes the path server and starts the dispatcher.
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
	pathDB, err := pathdbbe.New(config.PS.PathDB)
	if err != nil {
		log.Crit("Unable to initialize pathDB", "err", err)
		return 1
	}
	trustDB, err := trustdb.New(config.Trust.TrustDB)
	if err != nil {
		log.Crit("Unable to initialize trustDB", "err", err)
		return 1
	}
	topo := config.General.Topology
	trustConf := &trust.Config{
		LocalCSes: getAllCSAddresses(topo),
	}
	trustStore, err := trust.NewStore(trustDB, topo.ISD_AS,
		rand.Uint64(), trustConf, log.Root())
	if err != nil {
		log.Crit("Unable to initialize trust store", "err", err)
		return 1
	}
	err = snet.Init(topo.ISD_AS, "", "")
	if err != nil {
		log.Crit("Unable to initialize snet", "err", err)
		return 1
	}
	topoAddress := topo.PS.GetById(config.General.ID)
	publicAddr := env.GetPublicSnetAddress(topo.ISD_AS, topoAddress)
	bindAddr := env.GetBindSnetAddress(topo.ISD_AS, topoAddress)
	conn, err := snet.ListenSCIONWithBindSVC("udp4", publicAddr, bindAddr, addr.SvcPS)
	if err != nil {
		log.Crit("Unable to listen on SCION", "err", err)
		return 1
	}
	err = trustStore.LoadAuthoritativeTRC(filepath.Join(config.General.ConfigDir, "certs"))
	if err != nil {
		log.Crit("TRC error", "err", err)
		return 1
	}
	msger := messenger.New(
		topo.ISD_AS,
		disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		),
		trustStore,
		log.Root(),
		nil,
	)
	revCache := memrevcache.New(cache.NoExpiration, time.Second)
	trustStore.SetMessenger(msger)
	msger.AddHandler(infra.ChainRequest, trustStore.NewChainReqHandler(false))
	// TOOD(lukedirtwalker): with the new CP-PKI design the PS should no longer need to handle TRC
	// and cert requests.
	msger.AddHandler(infra.TRCRequest, trustStore.NewTRCReqHandler(false))
	args := handlers.HandlerArgs{
		PathDB:     pathDB,
		RevCache:   revCache,
		TrustStore: trustStore,
		Topology:   topo,
	}
	core := topo.Core
	var segReqHandler infra.Handler
	if core {
		segReqHandler = handlers.NewSegReqCoreHandler(args)
	} else {
		segReqHandler = handlers.NewSegReqNonCoreHandler(args)
	}
	msger.AddHandler(infra.SegRequest, segReqHandler)
	msger.AddHandler(infra.SegReg, handlers.NewSegRegHandler(args, config.PS.SegSync && core))
	msger.AddHandler(infra.IfStateInfos, handlers.NewIfStatInfoHandler(args))
	if config.PS.SegSync && core {
		msger.AddHandler(infra.SegSync, handlers.NewSyncHandler(args))
	}
	msger.AddHandler(infra.SegRev, handlers.NewRevocHandler(args))
	// Create a channel where prometheus can signal fatal errors
	fatalC := make(chan error, 1)
	config.Metrics.StartPrometheus(fatalC)
	// Start handling requests/messages
	go func() {
		defer log.LogPanicAndExit()
		msger.ListenAndServe()
	}()
	cleaner := periodic.StartPeriodicTask(cleaner.New(pathDB),
		time.NewTicker(300*time.Second), 295*time.Second)
	defer cleaner.Stop()
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
	if err := env.InitLogging(&config.Logging); err != nil {
		return err
	}
	// TODO(lukedirtwalker): SUPPORT RELOADING!!!
	environment = env.SetupEnv(nil)
	return nil
}

func getAllCSAddresses(topo *topology.Topo) []net.Addr {
	addrs := make([]net.Addr, 0, len(topo.CS))
	for _, server := range topo.CS {
		appAddr := server.PublicAddr(topo.Overlay)
		addrs = append(addrs, &snet.Addr{
			IA:   topo.ISD_AS,
			Host: appAddr,
		})
	}
	return addrs
}
