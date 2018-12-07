// Copyright 2016 ETH Zurich
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

// This file takes care of parsing command-line flags, setting up logging and
// signal handling, setting resource limits, and starting a new Router
// instance.

package main

import (
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"os/user"
	"syscall"

	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/profile"
)

var (
	id       = flag.String("id", "", "Element ID (Required. E.g. 'br4-ff00:0:2f')")
	confDir  = flag.String("confd", ".", "Configuration directory")
	profFlag = flag.Bool("profile", false, "Enable cpu and memory profiling")
	version  = flag.Bool("version", false, "Output version information and exit.")
)

func main() {
	os.Setenv("TZ", "UTC")
	// Parse and check flags.
	log.AddLogFileFlags()
	log.AddLogConsFlags()
	flag.Parse()
	if *version {
		fmt.Print(env.VersionInfo())
		os.Exit(0)
	}
	if *id == "" {
		log.Crit("No element ID specified")
		os.Exit(1)
	}
	if err := log.SetupFromFlags(*id); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	defer env.CleanupLog()
	if err := env.LogSvcStarted(common.BR, *id); err != nil {
		log.Crit("LogSvcStart failed", "err", err)
		log.Flush()
		os.Exit(1)
	}
	if err := checkPerms(); err != nil {
		log.Crit("Permissions checks failed", "err", err)
		log.Flush()
		os.Exit(1)
	}
	if *profFlag {
		// Start profiling if requested.
		profile.Start(*id)
	}
	setupSignals()
	r, err := NewRouter(*id, *confDir)
	if err != nil {
		log.Crit("Startup failed", "err", err)
		log.Flush()
		os.Exit(1)
	}
	if assert.On {
		log.Info("Router was built with assertions ON.")
	} else {
		log.Info("Router was built with assertions OFF.")
	}
	log.Info("Starting up", "id", *id, "pid", os.Getpid())
	if err := r.Run(); err != nil {
		log.Crit("Run failed", "err", err)
		log.Flush()
		os.Exit(1)
	}
}

func setupSignals() {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		defer log.LogPanicAndExit()
		<-sig
		env.LogSvcStopped(common.BR, *id)
		profile.Stop()
		log.Flush()
		os.Exit(1)
	}()
}

func checkPerms() error {
	user, err := user.Current()
	if err != nil {
		return common.NewBasicError("Error retrieving user", err)
	}
	if user.Uid == "0" {
		return common.NewBasicError("Running as root is not allowed for security reasons", nil)
	}
	return nil
}
