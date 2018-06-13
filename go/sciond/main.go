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
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/sciond/internal/servers"
)

const (
	ShutdownWaitTimeout = 5 * time.Second
)

type ConfigT struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	Trust   env.Trust
	SD      struct {
		// Address to listen on via the reliable socket protocol. If empty,
		// a reliable socket server is not started.
		Reliable string
		// Address to listen on for normal unixgram messages. If empty, a
		// unixgram server is not started.
		Unix string
		// If set, Bind is the preferred local address to listen on for SCION
		// messages.
		Bind snet.Addr
		// Public is the local address to listen on for SCION messages (if Bind is
		// not set), and to send out messages to other nodes.
		Public snet.Addr
	}
}

var Config ConfigT

var Environment *env.Env

var (
	flagConfig = flag.String("config", "", "Service TOML config file (required)")
)

func main() {
	os.Exit(realMain())
}

func Init(configName string) error {
	_, err := toml.DecodeFile(configName, &Config)
	if err != nil {
		return err
	}
	Environment, err = env.InitGeneral(&Config.General, nil)
	if err != nil {
		return err
	}
	err = env.InitLogging(&Config.Logging)
	if err != nil {
		return err
	}
	err = env.InitMetrics(&Config.Metrics)
	if err != nil {
		return err
	}
	if Config.SD.Reliable == "" {
		Config.SD.Reliable = "/run/shm/sciond/default.sock"
	}
	if Config.SD.Unix == "" {
		Config.SD.Unix = "/run/shm/sciond/default-unix.sock"
	}
	return nil
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

	// Initialize SignedCtrlPld server
	// FIXME(scrye): enable this once we have SCIOND-less snet and a TrustStore
	/*
		msger, err := NewMessenger(...)
		if err != nil {
			log.Crit("unable to initialize infra Messenger", "err", err)
			return 1
		}
		go msger.ListenAndServe()
	*/

	// Create a channel where server goroutines can signal fatal errors
	fatalC := make(chan error, 3)

	if Config.SD.Reliable != "" {
		server, shutdownF := NewServer("rsock", Config.SD.Reliable, log.Root())
		defer shutdownF()
		go func() {
			defer log.LogPanicAndExit()
			if err := server.ListenAndServe(); err != nil {
				fatalC <- common.NewBasicError("ReliableSockServer ListenAndServe error", nil,
					"err", err)
			}
		}()
	}

	if Config.SD.Unix != "" {
		server, shutdownF := NewServer("unixpacket", Config.SD.Unix, log.Root())
		defer shutdownF()
		go func() {
			defer log.LogPanicAndExit()
			if err := server.ListenAndServe(); err != nil {
				fatalC <- common.NewBasicError("UnixServer ListenAndServe error", nil, "err", err)
			}
		}()
	}

	if Config.Metrics.Prometheus != "" {
		go func() {
			defer log.LogPanicAndExit()
			if err := http.ListenAndServe(Config.Metrics.Prometheus, nil); err != nil {
				fatalC <- common.NewBasicError("HTTP ListenAndServe error", nil, "err", err)
			}
		}()
	}

	select {
	case <-Environment.AppShutdownSignal:
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

func NewMessenger(scionAddress string, logger log.Logger) (infra.Messenger, error) {
	// Initialize messenger for talking with other infra elements
	snetAddress, err := snet.AddrFromString(scionAddress)
	if err != nil {
		return nil, common.NewBasicError("snet address parse error", err)
	}
	conn, err := snet.ListenSCION("udp", snetAddress)
	if err != nil {
		return nil, common.NewBasicError("snet listen error", err)
	}
	dispatcher := disp.New(transport.NewPacketTransport(conn), messenger.DefaultAdapter, logger)
	// TODO: initialize actual trust store once it is available
	trustStore := infra.TrustStore(nil)
	return messenger.New(dispatcher, trustStore, logger), nil
}

func NewServer(network string, rsockPath string, logger log.Logger) (*servers.Server, func()) {
	// FIXME(scrye): enable msger below
	server := servers.NewServer(network, rsockPath, nil, logger)
	shutdownF := func() {
		ctx, cancelF := context.WithTimeout(context.Background(), ShutdownWaitTimeout)
		server.Shutdown(ctx)
		cancelF()
	}
	return server, shutdownF
}
