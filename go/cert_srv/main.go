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

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/common"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/trust"
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
	config   *conf.Conf
	store    *trust.Store
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
	if config, err = conf.Load(*id, *confDir); err != nil {
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
	dispatcher, err := NewDispatcher(config.PublicAddr, config.BindAddr)
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
			return common.NewBasicError("No SCIOND path specified", nil)
		}
	}
	if *confDir == "" {
		flag.Usage()
		return common.NewBasicError("No configuration directory specified", nil)
	}
	return nil
}

// initSNET initializes snet. The number of attempts is specified, as well as the sleep duration.
// This is needed, since supervisord might take some time, until sciond is initialized.
func initSNET(attempts int, sleep time.Duration) (err error) {
	// Initialize SCION local networking module
	for i := 0; i < attempts; i++ {
		if err = snet.Init(config.PublicAddr.IA, *sciondPath, *dispPath); err == nil {
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
