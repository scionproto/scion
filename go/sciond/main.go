// Copyright 2018 ETH Zurich
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
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
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

	pathDB, err := pathdb.New(config.SD.PathDB, "sqlite")
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
		rand.Uint64(), log.Root())
	if err != nil {
		log.Crit("Unable to initialize trust store", "err", err)
		return 1
	}
	err = snet.Init(config.General.Topology.ISD_AS, "", "/run/shm/dispatcher/default.sock")
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

	err = LoadAuthoritativeTRC(trustDB, trustStore)
	if err != nil {
		log.Crit("TRC error", "err", err)
		return 1
	}
	msger := messenger.New(
		disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		),
		trustStore,
		log.Root(),
	)
	trustStore.SetMessenger(msger)
	revCache := fetcher.NewRevCache(cache.NoExpiration, time.Second)
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
			),
		},
		proto.SCIONDMsg_Which_asInfoReq: &servers.ASInfoRequestHandler{
			TrustStore: trustStore,
			Messenger:  msger,
			Topology:   config.General.Topology,
		},
		proto.SCIONDMsg_Which_ifInfoRequest: &servers.IFInfoRequestHandler{
			Topology: config.General.Topology,
		},
		proto.SCIONDMsg_Which_serviceInfoRequest: &servers.SVCInfoRequestHandler{
			Topology: config.General.Topology,
		},
		proto.SCIONDMsg_Which_revNotification: &servers.RevNotificationHandler{
			RevCache: revCache,
		},
	}
	// Create a channel where server goroutines can signal fatal errors
	fatalC := make(chan error, 3)
	// Start servers
	rsockServer, shutdownF := NewServer("rsock", config.SD.Reliable, handlers, log.Root())
	defer shutdownF()
	go func() {
		defer log.LogPanicAndExit()
		if err := rsockServer.ListenAndServe(); err != nil {
			fatalC <- common.NewBasicError("ReliableSockServer ListenAndServe error", nil,
				"err", err)
		}
	}()
	unixpacketServer, shutdownF := NewServer("unixpacket", config.SD.Unix, handlers, log.Root())
	defer shutdownF()
	go func() {
		defer log.LogPanicAndExit()
		if err := unixpacketServer.ListenAndServe(); err != nil {
			fatalC <- common.NewBasicError("UnixServer ListenAndServe error", nil, "err", err)
		}
	}()
	if config.Metrics.Prometheus != "" {
		go func() {
			defer log.LogPanicAndExit()
			if err := http.ListenAndServe(config.Metrics.Prometheus, nil); err != nil {
				fatalC <- common.NewBasicError("HTTP ListenAndServe error", nil, "err", err)
			}
		}()
	}
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

func LoadAuthoritativeTRC(db *trustdb.DB, store infra.TrustStore) error {
	fileTRC, err := trc.TRCFromDir(
		filepath.Join(config.General.ConfigDir, "certs"),
		config.General.Topology.ISD_AS.I,
		func(err error) {
			log.Warn("Error reading TRC", "err", err)
		})
	if err != nil {
		return common.NewBasicError("Unable to load TRC from directory", err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	dbTRC, err := store.GetValidTRC(
		ctx,
		config.General.Topology.ISD_AS.I,
		config.General.Topology.ISD_AS.I,
	)
	cancelF()
	switch {
	case err != nil && common.GetErrorMsg(err) != trust.ErrEndOfTrail:
		// Unexpected error in trust store
		return err
	case common.GetErrorMsg(err) == trust.ErrEndOfTrail && fileTRC == nil:
		return common.NewBasicError("No TRC found on disk or in trustdb", nil)
	case common.GetErrorMsg(err) == trust.ErrEndOfTrail && fileTRC != nil:
		_, err := db.InsertTRC(fileTRC)
		return err
	case err == nil && fileTRC == nil:
		// Nothing to do, no TRC to load from file but we already have one in the DB
		return nil
	default:
		// Found a TRC file on disk, and found a TRC in the DB. Check versions.
		switch {
		case fileTRC.Version > dbTRC.Version:
			_, err := db.InsertTRC(fileTRC)
			return err
		case fileTRC.Version == dbTRC.Version:
			// Because it is the same version, check if the TRCs match
			eq, err := fileTRC.JSONEquals(dbTRC)
			if err != nil {
				return common.NewBasicError("Unable to compare TRCs", err)
			}
			if !eq {
				return common.NewBasicError("Conflicting TRCs found for same version", nil,
					"db", dbTRC, "file", fileTRC)
			}
			return nil
		default:
			// file TRC is older than DB TRC, so we just ignore it
			return nil
		}
	}
}
