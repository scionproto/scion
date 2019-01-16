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
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/config"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
	"github.com/scionproto/scion/go/sciond/internal/metrics"
	"github.com/scionproto/scion/go/sciond/internal/servers"
)

const (
	ShutdownWaitTimeout = 5 * time.Second
)

var (
	cfg         config.Config
	environment *env.Env
)

func init() {
	flag.Usage = env.Usage
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(config.Sample); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("SD", cfg.General.ID)
	defer log.LogPanicAndExit()
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	pathDB, revCache, err := pathstorage.NewPathStorage(cfg.SD.PathDB, cfg.SD.RevCache)
	if err != nil {
		log.Crit("Unable to initialize path storage", "err", err)
		return 1
	}
	trustDB, err := cfg.TrustDB.New()
	if err != nil {
		log.Crit("Unable to initialize trustDB", "err", err)
		return 1
	}
	trustStore, err := trust.NewStore(trustDB, cfg.General.Topology.ISD_AS, nil, log.Root())
	if err != nil {
		log.Crit("Unable to initialize trust store", "err", err)
		return 1
	}
	err = trustStore.LoadAuthoritativeTRC(filepath.Join(cfg.General.ConfigDir, "certs"))
	if err != nil {
		log.Crit("TRC error", "err", err)
		return 1
	}
	msger, err := infraenv.InitMessenger(
		cfg.General.Topology.ISD_AS,
		cfg.SD.Public,
		cfg.SD.Bind,
		addr.SvcNone,
		cfg.General.ReconnectToDispatcher,
		trustStore,
	)
	if err != nil {
		log.Crit(infraenv.ErrAppUnableToInitMessenger, "err", err)
		return 1
	}
	// Route messages to their correct handlers
	handlers := servers.HandlerMap{
		proto.SCIONDMsg_Which_pathReq: &servers.PathRequestHandler{
			Fetcher: fetcher.NewFetcher(
				msger,
				pathDB,
				trustStore,
				revCache,
				cfg.SD,
				log.Root(),
			),
		},
		proto.SCIONDMsg_Which_asInfoReq: &servers.ASInfoRequestHandler{
			TrustStore: trustStore,
		},
		proto.SCIONDMsg_Which_ifInfoRequest:      &servers.IFInfoRequestHandler{},
		proto.SCIONDMsg_Which_serviceInfoRequest: &servers.SVCInfoRequestHandler{},
		proto.SCIONDMsg_Which_revNotification: &servers.RevNotificationHandler{
			RevCache:   revCache,
			TrustStore: trustStore,
		},
	}
	cleaner := periodic.StartPeriodicTask(pathdb.NewCleaner(pathDB),
		periodic.NewTicker(300*time.Second), 295*time.Second)
	defer cleaner.Stop()
	rcCleaner := periodic.StartPeriodicTask(revcache.NewCleaner(revCache),
		periodic.NewTicker(10*time.Second), 10*time.Second)
	defer rcCleaner.Stop()
	// Start servers
	rsockServer, shutdownF := NewServer("rsock", cfg.SD.Reliable, handlers, log.Root())
	defer shutdownF()
	StartServer("ReliableSockServer", cfg.SD.Reliable, rsockServer)
	unixpacketServer, shutdownF := NewServer("unixpacket", cfg.SD.Unix, handlers, log.Root())
	defer shutdownF()
	StartServer("UnixServer", cfg.SD.Unix, unixpacketServer)
	cfg.Metrics.StartPrometheus()
	select {
	case <-environment.AppShutdownSignal:
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		// Deferred shutdowns for all running servers run now.
		return 0
	case <-fatal.Chan():
		return 1
	}
}

func setupBasic() error {
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return err
	}
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	metrics.Init(cfg.General.ID)
	return env.LogAppStarted("SD", cfg.General.ID)
}

func setup() error {
	if err := env.InitGeneral(&cfg.General); err != nil {
		return err
	}
	itopo.SetCurrentTopology(cfg.General.Topology)
	environment = infraenv.InitInfraEnvironment(cfg.General.TopologyPath)
	cfg.InitDefaults()
	return cfg.SD.CreateSocketDirs()
}

func NewServer(network string, rsockPath string, handlers servers.HandlerMap,
	logger log.Logger) (*servers.Server, func()) {

	server := servers.NewServer(network, rsockPath, handlers, logger)
	shutdownF := func() {
		ctx, cancelF := context.WithTimeout(context.Background(), ShutdownWaitTimeout)
		server.Shutdown(ctx)
		cancelF()
	}
	return server, shutdownF
}

func StartServer(name, sockPath string, server *servers.Server) {
	go func() {
		defer log.LogPanicAndExit()
		if cfg.SD.DeleteSocket {
			if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
				fatal.Fatal(common.NewBasicError(name+" SocketRemoval error", err))
			}
		}
		if err := server.ListenAndServe(); err != nil {
			fatal.Fatal(common.NewBasicError(name+" ListenAndServe error", err))
		}
	}()
}
