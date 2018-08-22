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
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/path_srv/internal/handlers"
	"github.com/scionproto/scion/go/proto"
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
	pathDB, err := pathdb.New(config.PS.PathDB, "sqlite")
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
		LocalCSes: topo.GetAllServerAddresses(proto.ServiceType_cs),
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
	topoAddress := topo.GetTopoAddr(proto.ServiceType_ps, config.General.ID)
	publicAddr := env.GetPublicSnetAddress(topo.ISD_AS, topoAddress)
	// Use nil bind addr, since it is the same as the public addr,
	// and that would lead to a dispatcher problem.
	conn, err := snet.ListenSCIONWithBindSVC("udp4", publicAddr, nil, addr.SvcPS)
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
	args := &handlers.HandlerArgs{
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
		segReqHandler = handlers.NewSegReqLocalHandler(args)
	}
	msger.AddHandler(infra.PathSegmentRequest, segReqHandler)
	msger.AddHandler(infra.PathSegmentRegistration,
		handlers.NewSegRegHandler(args, config.PS.SegSync && core))
	if config.PS.SegSync && core {
		msger.AddHandler(infra.PathSynchronization, handlers.NewSyncHandler(args))
	}
	msger.AddHandler(infra.PathSegmentRevocation, handlers.NewRevocHandler(args))
	// Create a channel where prometheus can signal fatal errors
	fatalC := make(chan error, 1)
	config.Metrics.StartPrometheus(fatalC)
	// Start handling requests/messages
	go func() {
		defer log.LogPanicAndExit()
		msger.ListenAndServe()
	}()
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
	_, err := toml.DecodeFile(configName, &config)
	if err != nil {
		return err
	}
	err = env.InitGeneral(&config.General)
	if err != nil {
		return err
	}
	err = env.InitLogging(&config.Logging)
	if err != nil {
		return err
	}
	environment = env.SetupEnv(nil)
	return nil
}
