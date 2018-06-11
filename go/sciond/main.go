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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/env"
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
	env.Config
	SD struct {
		// Address to listen on via the reliable socket protocol. If empty,
		// a reliable socket server is not started.
		Reliable string
		// Address to listen on for normal unixgram messages. If empty, a
		// unixgram server is not started.
		Unix string
	}
}

var (
	flagConfig = flag.String("config", "", "Service TOML config file (required)")

	config ConfigT
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
	if err := env.LoadConfig(os.Stderr, *flagConfig, &config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	environment, err := env.Init(&config.Config, nil)
	if err != nil {
		log.Crit("Error", "err", err)
		flag.Usage()
		return 1
	}
	defer log.LogPanicAndExit()

	// Initialize SignedCtrlPld server
	// FIXME(scrye): enable this once we have SCIOND-less snet and a TrustStore
	/*
		msger, err := NewMessenger(*scionAddress, Env)
		if err != nil {
			log.Crit("unable to initialize infra Messenger", "err", err)
			return 1
		}
		go msger.ListenAndServe()
	*/

	// Create a channel where server goroutines can signal fatal errors
	fatalC := make(chan error, 3)

	if config.SD.Reliable != "" {
		server, shutdownF := NewServer("rsock", config.SD.Reliable, environment)
		defer shutdownF()
		go func() {
			defer log.LogPanicAndExit()
			if err := server.ListenAndServe(); err != nil {
				fatalC <- common.NewBasicError("ReliableSockServer ListenAndServe error", nil,
					"err", err)
			}
		}()
	}

	if config.SD.Unix != "" {
		server, shutdownF := NewServer("unixpacket", config.SD.Unix, environment)
		defer shutdownF()
		go func() {
			defer log.LogPanicAndExit()
			if err := server.ListenAndServe(); err != nil {
				fatalC <- common.NewBasicError("UnixServer ListenAndServe error", nil, "err", err)
			}
		}()
	}

	if environment.HTTPAddress != "" {
		go func() {
			defer log.LogPanicAndExit()
			if err := http.ListenAndServe(environment.HTTPAddress, nil); err != nil {
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

func NewMessenger(scionAddress string, env *env.Env) (infra.Messenger, error) {
	// Initialize messenger for talking with other infra elements
	snetAddress, err := snet.AddrFromString(scionAddress)
	if err != nil {
		return nil, common.NewBasicError("snet address parse error", err)
	}
	conn, err := snet.ListenSCION("udp", snetAddress)
	if err != nil {
		return nil, common.NewBasicError("snet listen error", err)
	}
	dispatcher := disp.New(transport.NewPacketTransport(conn), messenger.DefaultAdapter, env.Log)
	// TODO: initialize actual trust store once it is available
	trustStore := infra.TrustStore(nil)
	return messenger.New(dispatcher, trustStore, env.Log), nil
}

func NewServer(network string, rsockPath string, env *env.Env) (*servers.Server, func()) {
	// FIXME(scrye): enable msger below
	server := servers.NewServer(network, rsockPath, nil, env.Log)
	shutdownF := func() {
		ctx, cancelF := context.WithTimeout(context.Background(), ShutdownWaitTimeout)
		server.Shutdown(ctx)
		cancelF()
	}
	return server, shutdownF
}
