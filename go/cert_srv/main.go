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
	"fmt"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

const (
	initAttempts = 100
	initInterval = time.Second
)

var (
	id         = flag.String("id", "", "Element ID (Required. E.g. 'cs4-ff00:0:2f')")
	sciondPath = flag.String("sciond", "",
		"SCIOND socket path (Optional if SCIOND_PATH is set)")
	dispPath = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"SCION Dispatcher path")
	confDir  = flag.String("confd", "", "Configuration directory (Required)")
	cacheDir = flag.String("cached", "gen-cache", "Caching directory")
	stateDir = flag.String("stated", "", "State directory (Defaults to confd)")
	prom     = flag.String("prom", "127.0.0.1:1282", "Address to export prometheus metrics on")
	disp     *Dispatcher
	sighup   chan os.Signal
)

func init() {
	// Add a SIGHUP handler as soon as possible on startup, to reduce the
	// chance that a premature SIGHUP will kill the process. This channel is
	// used by configSig below.
	sighup = make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
}

// main initializes the certificate server and starts the dispatcher.
func main() {
	var err error
	os.Setenv("TZ", "UTC")
	log.AddLogFileFlags()
	log.AddLogConsFlags()
	flag.Parse()
	if *id == "" {
		log.Crit("No element ID specified")
		flag.Usage()
		os.Exit(1)
	}
	if err = log.SetupFromFlags(*id); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	defer log.LogPanicAndExit()
	setupSignals()
	if err = checkFlags(); err != nil {
		fatal(err.Error())
	}
	if err = setup(); err != nil {
		fatal("Setup failed", "err", err.Error())
	}
	var wait chan struct{}
	<-wait
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
	if *stateDir == "" {
		*stateDir = *confDir
	}
	return nil
}

// setupSignals handle signals.
func setupSignals() {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		log.Flush()
		os.Exit(1)
	}()
	go configSig()
}

func configSig() {
	defer log.LogPanicAndExit()
	for range sighup {
		log.Info("Reload config")
		if err := setup(); err != nil {
			fatal("Unable to reload config", "err", err.Error())
		}
		log.Info("Config reloaded")
	}
}

func fatal(msg string, args ...interface{}) {
	log.Crit(msg, args...)
	log.Flush()
	os.Exit(1)
}
