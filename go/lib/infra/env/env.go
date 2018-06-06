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
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/scionproto/scion/go/lib/log"
)

var sighupC chan os.Signal

func init() {
	os.Setenv("TZ", "UTC")

	sighupC = make(chan os.Signal, 1)
	signal.Notify(sighupC, syscall.SIGHUP)
}

// Env aggregates command-line flags, config information and
// environment variables (if any are ever needed).
type Env struct {
	// Config contains the information loaded from the server's config file.
	Config *Config
	// Root logger (conforms to log15 Logger interface)
	Log log.Logger
	// Address to run the local HTTP server on (e.g., for Prometheus)
	HTTPAddress string
	// AppShutdownSignal is closed when the process receives a signal to close
	// (e.g., SIGTERM).
	AppShutdownSignal chan struct{}
}

// Init performs common set up for infra services. This includes parsing and
// validating flags, loading the service config, setting up logging, and
// setting up signals.
//
// On SIGHUP, reloadF is called in a fresh goroutine. SIGHUP signals are not
// buffered pending registration, and might be drained before the function is
// registered. Function reloadF itself must ensure that panics are logged.
func Init(cfg *Config, reloadF func()) (*Env, error) {
	env := &Env{
		Config: cfg,
	}
	if err := env.setupLogging(); err != nil {
		return nil, err
	}
	env.setupSignals(reloadF)
	if env.Config.Logging.Metrics.Prometheus != "" {
		env.HTTPAddress = env.Config.Logging.Metrics.Prometheus
	}
	return env, nil
}

// setupLogging initializes logging and sets the root logger Log.
func (env *Env) setupLogging() error {
	if env.Config.Logging.File.Level != "" {
		err := log.SetupLogFile(
			filepath.Base(env.Config.Logging.File.Path),
			filepath.Dir(env.Config.Logging.File.Path),
			env.Config.Logging.File.Level,
			int(env.Config.Logging.File.Size),
			int(env.Config.Logging.File.MaxAge),
			int(env.Config.Logging.File.FlushInterval),
		)
		if err != nil {
			return err
		}
	}

	if env.Config.Logging.Console.Level != "" {
		err := log.SetupLogConsole(env.Config.Logging.Console.Level)
		if err != nil {
			return err
		}
	}

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
