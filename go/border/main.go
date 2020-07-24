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
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/user"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/service"
)

var (
	cfg brconf.Config
	r   *Router
)

func init() {
	flag.Usage = env.Usage
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(&cfg); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped(common.BR, cfg.General.ID)
	defer log.HandlePanic()

	// Start HTTP endpoints.
	statusPages := service.StatusPages{
		"info":     service.NewInfoHandler(),
		"config":   service.NewConfigHandler(cfg),
		"status":   statusHandler,
		"topology": itopo.TopologyHandler,
	}
	if err := statusPages.Register(http.DefaultServeMux, cfg.General.ID); err != nil {
		log.Error("registering status pages", "err", err)
		return 1
	}

	if err := setup(); err != nil {
		log.Error("Setup failed", "err", err)
		return 1
	}
	if err := checkPerms(); err != nil {
		log.Error("Permissions checks failed", "err", err)
		return 1
	}
	var err error
	if r, err = NewRouter(cfg.General.ID, cfg.General.ConfigDir); err != nil {
		log.Error("Startup failed", "err", err)
		return 1
	}
	if assert.On {
		log.Info("Router was built with assertions ON.")
	} else {
		log.Info("Router was built with assertions OFF.")
	}
	r.Start()
	select {
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

func setupBasic() error {
	if err := libconfig.LoadFile(env.ConfigFile(), &cfg); err != nil {
		return serrors.WrapStr("Failed to load config", err, "file", env.ConfigFile())
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		return serrors.WrapStr("Failed to initialize logging", err)
	}
	prom.ExportElementID(cfg.General.ID)
	return env.LogAppStarted(common.BR, cfg.General.ID)
}

func setup() error {
	if err := cfg.Validate(); err != nil {
		return common.NewBasicError("Unable to validate config", err)
	}
	env.SetupEnv(func() {
		if r == nil {
			log.Error("Unable to reload config", "err", "router not set")
			return
		}
		if err := r.ReloadConfig(); err != nil {
			log.Error("Unable to reload config", "err", err)
			return
		}
		log.Info("Config reloaded")
	})
	return nil
}

func checkPerms() error {
	u, err := user.Current()
	if err != nil {
		return common.NewBasicError("Error retrieving user", err)
	}
	if u.Uid == "0" {
		return serrors.New("Running as root is not allowed for security reasons")
	}
	return nil
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	states := ifstate.LoadStates()
	out := "Interfaces:\n"
	for _, state := range states {
		status := "active"
		if !state.Active {
			status = "disabled"
		}
		out += fmt.Sprintf("  %-5v %s\n", state.IfID, status)
	}
	out += "\n"
	fmt.Fprint(w, out)
}
