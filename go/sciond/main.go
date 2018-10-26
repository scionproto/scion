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
	"math/rand"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/modules/cleaner"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
	"github.com/scionproto/scion/go/sciond/internal/sdconfig"
	"github.com/scionproto/scion/go/sciond/internal/servers"
)

const (
	ShutdownWaitTimeout = 5 * time.Second
)

type Config struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	Trust   env.Trust
	SD      sdconfig.Config
}

var (
	config      Config
	environment *env.Env
)

func init() {
	flag.Usage = env.Usage
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(sdconfig.Sample); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer env.CleanupLog()
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	pathDB, revCache, err := pathstorage.NewPathStorage(config.SD.PathDB, config.SD.RevCache)
	if err != nil {
		log.Crit("Unable to initialize path storage", "err", err)
		return 1
	}
	trustDB, err := trustdb.New(config.Trust.TrustDB)
	if err != nil {
		log.Crit("Unable to initialize trustDB", "err", err)
		return 1
	}
	trustStore, err := trust.NewStore(trustDB, config.General.Topology.ISD_AS,
		rand.Uint64(), nil, log.Root())
	if err != nil {
		log.Crit("Unable to initialize trust store", "err", err)
		return 1
	}
	err = trustStore.LoadAuthoritativeTRC(filepath.Join(config.General.ConfigDir, "certs"))
	if err != nil {
		log.Crit("TRC error", "err", err)
		return 1
	}
	msger, err := infraenv.InitMessenger(
		config.General.Topology.ISD_AS,
		config.SD.Public,
		config.SD.Bind,
		addr.SvcNone,
		config.General.ReconnectToDispatcher,
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
				config.SD,
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
	// Create a channel where server goroutines can signal fatal errors
	fatalC := make(chan error, 3)
	cleaner := periodic.StartPeriodicTask(cleaner.New(pathDB),
		time.NewTicker(300*time.Second), 295*time.Second)
	defer cleaner.Stop()
	// Start servers
	rsockServer, shutdownF := NewServer("rsock", config.SD.Reliable, handlers, log.Root())
	defer shutdownF()
	StartServer("ReliableSockServer", config.SD.Reliable, rsockServer, fatalC)
	unixpacketServer, shutdownF := NewServer("unixpacket", config.SD.Unix, handlers, log.Root())
	defer shutdownF()
	StartServer("UnixServer", config.SD.Unix, unixpacketServer, fatalC)
	config.Metrics.StartPrometheus(fatalC)
	select {
	case <-environment.AppShutdownSignal:
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		// Deferred shutdowns for all running servers run now.
		return 0
	case err := <-fatalC:
		// At least one of the servers was unable to run or encountered a
		// fatal error while running.
		log.Crit("Unable to listen and serve", "err", err)
		return 1
	}
}

func setupBasic() error {
	if _, err := toml.DecodeFile(env.ConfigFile(), &config); err != nil {
		return err
	}
	if err := env.InitLogging(&config.Logging); err != nil {
		return err
	}
	env.LogSvcStarted("SD", config.General.ID)
	return nil
}

func setup() error {
	if err := env.InitGeneral(&config.General); err != nil {
		return err
	}
	itopo.SetCurrentTopology(config.General.Topology)
	environment = infraenv.InitInfraEnvironment(config.General.TopologyPath)
	config.SD.InitDefaults()
	return config.SD.CreateSocketDirs()
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

func StartServer(name, sockPath string, server *servers.Server, fatalC chan error) {
	go func() {
		defer log.LogPanicAndExit()
		if config.SD.DeleteSocket {
			if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
				fatalC <- common.NewBasicError(name+" SocketRemoval error", err)
			}
		}
		if err := server.ListenAndServe(); err != nil {
			fatalC <- common.NewBasicError(name+" ListenAndServe error", err)
		}
	}()
}
