// Copyright 2018 ETH Zurich
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
	"context"
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
	"github.com/scionproto/scion/go/sciond/internal/servers"
)

const (
	ShutdownWaitTimeout = 5 * time.Second
)

var _ env.Config = (*Config)(nil)

type Config struct {
	G  env.General `toml:"General"`
	L  env.Logging `toml:"Logging"`
	M  env.Metrics `toml:"Metrics"`
	T  env.Trust   `toml:"Trust"`
	SD struct {
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

func (c *Config) General() *env.General {
	return &c.G
}

func (c *Config) Logging() *env.Logging {
	return &c.L
}

func (c *Config) Metrics() *env.Metrics {
	return &c.M
}

func (c *Config) Trust() *env.Trust {
	return &c.T
}

func (c *Config) PathDB() string {
	return c.SD.PathDB
}

func (c *Config) Public() *snet.Addr {
	return c.SD.Public
}

func (c *Config) Bind() *snet.Addr {
	return c.SD.Bind
}

var (
	config      Config
	environment *env.Env
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	if err := Init(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		return 1
	}
	defer log.LogPanicAndExit()
	pathDB, msger, trustStore, err := env.InitConnections(&config)
	if err != nil {
		return 1
	}
	revCache := fetcher.NewRevCache(cache.NoExpiration, time.Second)
	// Route messages to their correct handlers
	handlers := servers.HandlerMap{
		proto.SCIONDMsg_Which_pathReq: &servers.PathRequestHandler{
			Fetcher: fetcher.NewFetcher(
				// FIXME(scrye): This doesn't allow for topology updates. When
				// reloading support is implemented, fresh topology information
				// should be loaded from file.
				config.General().Topology,
				msger,
				pathDB,
				trustStore,
				revCache,
			),
		},
		proto.SCIONDMsg_Which_asInfoReq: &servers.ASInfoRequestHandler{
			TrustStore: trustStore,
			Messenger:  msger,
			Topology:   config.General().Topology,
		},
		proto.SCIONDMsg_Which_ifInfoRequest: &servers.IFInfoRequestHandler{
			Topology: config.General().Topology,
		},
		proto.SCIONDMsg_Which_serviceInfoRequest: &servers.SVCInfoRequestHandler{
			Topology: config.General().Topology,
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
	StartServer("ReliableSockServer", config.SD.Reliable, rsockServer, fatalC)
	unixpacketServer, shutdownF := NewServer("unixpacket", config.SD.Unix, handlers, log.Root())
	defer shutdownF()
	StartServer("UnixServer", config.SD.Unix, unixpacketServer, fatalC)
	env.StartPrometheus(&config, fatalC)
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

func Init() error {
	var err error
	environment, err = env.Init(&config, nil)
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
			if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
				if err := os.Remove(sockPath); err != nil {
					fatalC <- common.NewBasicError(name+" SocketRemoval error", err)
				}
			}
		}
		if err := server.ListenAndServe(); err != nil {
			fatalC <- common.NewBasicError(name+" ListenAndServe error", err)
		}
	}()
}
