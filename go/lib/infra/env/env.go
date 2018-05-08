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

// Package environment contains common command line and initialization code for
// SCION Infrastructure services. If something is specific to one app, it
// should go into that app's code and not here.
//
// During initialization, SIGHUPs are masked. To call a function on each
// SIGHUP, pass the function when calling Init.
//
// TODO(scrye): Also common stuff like trustdb initialization, messenger
// initialization and handler registration can go here. Everything that can be
// shared by infra apps, to reduce duplicated code.
package env

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	liblog "github.com/scionproto/scion/go/lib/log"
)

var sighupC chan os.Signal

func init() {
	sighupC = make(chan os.Signal, 1)
	signal.Notify(sighupC, syscall.SIGHUP)
}

var (
	id = flag.String("id", "", "Element ID (e.g., 'cs4-ff00:0:2f'). (Required)")
	// FIXME(scrye): Enable this when config loading is needed
	//confDir      = flag.String("confd", "", "Configuration directory (Required)")
	// FIXME(scrye): Enable this when trust store becomes available.
	//databasePath = flag.String("trustdb", "trust.db", "Trust database file")
	prom = flag.String("prom", "",
		"Address to export prometheus metrics on. If not set, metrics are not exported.")
)

// Env aggregates command-line flags, config information and
// environment variables (if any are ever needed).
type Env struct {
	// Element ID, used for determining the name of the logging files
	ID string
	// Root logger (conforms to log15 Logger interface)
	Log log.Logger
	// Address to run the local HTTP server on (e.g., for Prometheus)
	HTTPAddress string
	// AppShutdownSignal is closed when the process receives a signal to close
	// (e.g., SIGTERM).
	AppShutdownSignal chan struct{}
}

// Init performs common set up for infra services. This includes parsing and
// validating flags and environment variables, setting up logging, and setting
// up signals.
//
// On SIGHUP, reloadF is called in a fresh goroutine. SIGHUP signals are not
// buffered pending registration, and might be drained before the function is
// registered.  Function reloadF itself must ensure that panics are logged.
func Init(reloadF func()) (*Env, error) {
	env := &Env{}
	liblog.AddDefaultLogFlags()
	flag.Parse()
	if err := env.setupLogging(); err != nil {
		return nil, err
	}
	env.setupSignals(reloadF)
	env.HTTPAddress = *prom
	return env, nil
}

// setupLogging initializes logging and sets the root logger Log.
func (env *Env) setupLogging() error {
	if *id == "" {
		return common.NewBasicError("No element ID specified", nil)
	}
	env.ID = *id
	liblog.Setup(env.ID)
	env.Log = log.Root()
	return nil
}

// setupSignals sets up a goroutine that closes AppShutdownSignal if
// SIGTERM/SIGINT signals are received by the app.
func (env *Env) setupSignals(reloadF func()) {
	env.AppShutdownSignal = make(chan struct{})
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		close(env.AppShutdownSignal)
	}()
	go func() {
		<-sighupC
		log.Info("Received config reload signal")
		if reloadF != nil {
			go reloadF()
		}
	}()
}
