// Copyright 2017 ETH Zurich
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
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	_ "github.com/scionproto/scion/go/lib/scrypto" // Make sure math/rand is seeded
)

const (
	initAttempts = 100
	initInterval = time.Second
)

var (
	id         = flag.String("id", "", "Element ID (Required. E.g. 'cs4-ff00:0:2f')")
	sciondPath = flag.String("sciond", sciond.GetDefaultSCIONDPath(nil), "SCIOND socket path")
	dispPath   = flag.String("dispatcher", "", "SCION Dispatcher path")
	confDir    = flag.String("confd", "", "Configuration directory (Required)")
	cacheDir   = flag.String("cached", "gen-cache", "Caching directory")
	stateDir   = flag.String("stated", "", "State directory (Defaults to confd)")
	prom       = flag.String("prom", "127.0.0.1:1282", "Address to export prometheus metrics on")
	reissReq   *ReissRequester
	sighup     chan os.Signal
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
	select {}
}

// checkFlags checks that all required flags are set.
func checkFlags() error {
	if *sciondPath == "" {
		flag.Usage()
		return common.NewBasicError("No SCIOND path specified", nil)
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
		defer log.LogPanicAndExit()
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		log.Flush()
		os.Exit(1)
	}()
	go func() {
		defer log.LogPanicAndExit()
		configSig()
	}()
}

func configSig() {
	for range sighup {
		log.Info("Reloading is not supported")
	}
}

func fatal(msg string, args ...interface{}) {
	log.Crit(msg, args...)
	log.Flush()
	os.Exit(1)
}
