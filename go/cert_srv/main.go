// Copyright 2017 ETH Zurich
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
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/trust"
)

const (
	initAttempts = 100
	initInterval = time.Second
)

var (
	id         = flag.String("id", "", "Element ID (Required. E.g. 'cs1-10-1')")
	sciondPath = flag.String("sciond", "",
		"SCIOND socket path (Optional if SCIOND_PATH is set)")
	dispPath = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"SCION Dispatcher path")
	confDir  = flag.String("confd", "", "Configuration directory (Required)")
	cacheDir = flag.String("cached", "gen-cache", "Caching directory")
	prom     = flag.String("prom", "127.0.0.1:1282", "Address to export prometheus metrics on")
	topo     *topology.Topo
	store    *trust.Store
	local    *snet.Addr
)

// main initializes the certificate server and starts the dispatcher.
func main() {
	flag.Parse()
	if *id == "" {
		log.Crit("No element ID specified")
		flag.Usage()
		os.Exit(1)
	}
	liblog.Setup(*id)
	defer liblog.LogPanicAndExit()
	setupSignals()
	var err error
	if err = checkFlags(); err != nil {
		fatal(err.Error())
	}
	if err = loadTopo(); err != nil {
		fatal(err.Error())
	}
	// initialize Trust Store
	if store, err = trust.NewStore(filepath.Join(*confDir, "certs"), *cacheDir, *id); err != nil {
		fatal("Unable to initialize TrustStore", "err", err)
	}
	// initialize snet with retries
	if err = initSNET(initAttempts, initInterval); err != nil {
		fatal("Unable to create local SCION Network context", "err", err)
	}
	// initialize dispatcher
	dispatcher, err := NewDispatcher(local)
	if err != nil {
		fatal("Unable to initialize dispatcher", "err", err)
	}
	dispatcher.run()

}

// checkFlags checks that all required flags are set.
func checkFlags() error {
	if *sciondPath == "" {
		*sciondPath = os.Getenv("SCIOND_PATH")
		if *sciondPath == "" {
			flag.Usage()
			return common.NewCError("No SCIOND path specified")
		}
	}
	if *confDir == "" {
		flag.Usage()
		return common.NewCError("No configuration directory specified")
	}
	return nil
}

// loadTopo loads topology from the configuration file and sets the local address.
func loadTopo() (err error) {
	if topo, err = topology.LoadFromFile(filepath.Join(*confDir, topology.CfgName)); err != nil {
		return common.NewCError("Unable to load topology", "err", err)
	}
	topoAddr, ok := topo.CS[*id]
	if !ok {
		return common.NewCError("Unable to load BindAddress. Element ID not found",
			"id", *id)
	}
	bindInfo := topoAddr.BindAddrInfo(topo.Overlay)
	local = &snet.Addr{IA: topo.ISD_AS, Host: addr.HostFromIP(bindInfo.IP),
		L4Port: uint16(bindInfo.L4Port)}
	return nil
}

// initSNET initializes snet. The number of attempts is specified, as well as the sleep duration.
// This is needed, since supervisord might take some time, until sciond is initialized.
func initSNET(attempts int, sleep time.Duration) (err error) {
	// Initialize SCION local networking module
	for i := 0; i < attempts; i++ {
		if err = snet.Init(local.IA, *sciondPath, *dispPath); err == nil {
			break
		}
		log.Error("Unable to initialize snet", "Retry interval", sleep, "err", err)
		time.Sleep(sleep)
	}
	return err
}

// setupSignals handle signals.
func setupSignals() {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		liblog.Flush()
		os.Exit(1)
	}()
}

func fatal(msg string, args ...interface{}) {
	log.Crit(msg, args...)
	liblog.Flush()
	os.Exit(1)
}
