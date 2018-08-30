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
	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	pathdbbe "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
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
	SD      struct {
		// Address to listen on via the reliable socket protocol. If empty,
		// a reliable socket server on the default socket is started.
		Reliable string
		// Address to listen on for normal unixgram messages. If empty, a
		// unixgram server on the default socket is started.
		Unix string
		// If set to True, the socket is removed before being created
		DeleteSocket bool
		// Public is the local address to listen on for SCION messages (if Bind is
		// not set), and to send out messages to other nodes.
		Public *snet.Addr
		// If set, Bind is the preferred local address to listen on for SCION
		// messages.
		Bind *snet.Addr
		// PathDB contains the file location  of the path segment database.
		PathDB string
	}
}

var config Config

var environment *env.Env

var (
	flagConfig = flag.String("config", "", "Service TOML config file (required)")
)

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
	if err := Init(*flagConfig); err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		return 1
	}
	defer log.LogPanicAndExit()

	pathDB, err := pathdbbe.New(config.SD.PathDB)
	if err != nil {
		log.Crit("Unable to initialize pathDB", "err", err)
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
	err = snet.Init(config.General.Topology.ISD_AS, "", "")
	if err != nil {
		log.Crit("Unable to initialize snet", "err", err)
		return 1
	}
	conn, err := snet.ListenSCIONWithBindSVC("udp4", config.SD.Public,
		config.SD.Bind, addr.SvcNone)
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
		config.General.Topology.ISD_AS,
		disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		),
		trustStore,
		log.Root(),
		nil,
	)
	trustStore.SetMessenger(msger)
	revCache := memrevcache.New(cache.NoExpiration, time.Second)
	// Route messages to their correct handlers
	handlers := servers.HandlerMap{
		proto.SCIONDMsg_Which_pathReq: &servers.PathRequestHandler{
			Fetcher: fetcher.NewFetcher(
				// FIXME(scrye): This doesn't allow for topology updates. When
				// reloading support is implemented, fresh topology information
				// should be loaded from file.
				config.General.Topology,
				msger,
				pathDB,
				trustStore,
				revCache,
				log.Root(),
			),
		},
		proto.SCIONDMsg_Which_asInfoReq: &servers.ASInfoRequestHandler{
			TrustStore: trustStore,
			Topology:   config.General.Topology,
		},
		proto.SCIONDMsg_Which_ifInfoRequest: &servers.IFInfoRequestHandler{
			Topology: config.General.Topology,
		},
		proto.SCIONDMsg_Which_serviceInfoRequest: &servers.SVCInfoRequestHandler{
			Topology: config.General.Topology,
		},
		proto.SCIONDMsg_Which_revNotification: &servers.RevNotificationHandler{
			RevCache:   revCache,
			TrustStore: trustStore,
		},
	}
	// Create a channel where server goroutines can signal fatal errors
	fatalC := make(chan error, 3)
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

func Init(configName string) error {
	_, err := toml.DecodeFile(configName, &config)
	if err != nil {
		return err
	}
	err = env.InitGeneral(&config.General)
	if err != nil {
		return err
	}
	environment = env.SetupEnv(nil)
	err = env.InitLogging(&config.Logging)
	if err != nil {
		return err
	}
	if config.SD.Reliable == "" {
		config.SD.Reliable = sciond.DefaultSCIONDPath
	}
	if config.SD.Unix == "" {
		config.SD.Unix = "/run/shm/sciond/default-unix.sock"
	}
	return nil
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
