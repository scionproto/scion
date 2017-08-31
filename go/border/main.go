// Copyright 2016 ETH Zurich
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

// This file takes care of parsing command-line flags, setting up logging and
// signal handling, setting resource limits, and starting a new Router
// instance.

package main

import (
	"flag"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/assert"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/profile"
)

var (
	id       = flag.String("id", "", "Element ID (Required. E.g. 'br4-21-9')")
	confDir  = flag.String("confd", ".", "Configuration directory")
	profFlag = flag.Bool("profile", false, "Enable cpu and memory profiling")
)

func main() {
	// Parse and check flags.
	flag.Parse()
	if *id == "" {
		log.Crit("No element ID specified")
		os.Exit(1)
	}
	liblog.Setup(*id)
	defer liblog.LogPanicAndExit()
	if *profFlag {
		// Start profiling if requested.
		profile.Start(*id)
	}
	setupSignals()
	r, err := NewRouter(*id, *confDir)
	if err != nil {
		log.Crit("Startup failed", err.Ctx...)
		liblog.Flush()
		os.Exit(1)
	}
	if assert.On {
		log.Info("Router was built with assertions ON.")
	} else {
		log.Info("Router was built with assertions OFF.")
	}
	log.Info("Starting up", "id", *id, "pid", os.Getpid())
	if err := r.Run(); err != nil {
		log.Crit("Run failed", err.Ctx...)
		liblog.Flush()
		os.Exit(1)
	}
}

func setupSignals() {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		<-sig
		log.Info("Exiting")
		profile.Stop()
		liblog.Flush()
		os.Exit(1)
	}()
}
