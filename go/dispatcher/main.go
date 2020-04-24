// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"bytes"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/user"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/dispatcher/config"
	"github.com/scionproto/scion/go/dispatcher/network"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	cfg config.Config
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if returnCode, ok := env.CheckFlags(&cfg); !ok {
		return returnCode
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("Dispatcher", cfg.Dispatcher.ID)
	defer log.HandlePanic()
	if err := cfg.Validate(); err != nil {
		log.Crit("Unable to validate config", "err", err)
		return 1
	}

	if err := checkPerms(); err != nil {
		log.Crit("Permissions checks failed", "err", err)
		return 1
	}

	if err := util.CreateParentDirs(cfg.Dispatcher.ApplicationSocket); err != nil {
		log.Crit("Unable to create directory tree for socket", "err", err)
		return 1
	}

	go func() {
		defer log.HandlePanic()
		err := RunDispatcher(
			cfg.Dispatcher.DeleteSocket,
			cfg.Dispatcher.ApplicationSocket,
			os.FileMode(cfg.Dispatcher.SocketFileMode),
			cfg.Dispatcher.UnderlayPort,
		)
		if err != nil {
			fatal.Fatal(err)
		}
	}()

	env.SetupEnv(nil)
	http.HandleFunc("/config", configHandler)
	http.HandleFunc("/info", env.InfoHandler)
	cfg.Metrics.StartPrometheus()

	returnCode := waitForTeardown()
	// XXX(scrye): if the dispatcher is shut down on purpose, it is usually
	// done together with the whole stack on top the dispatcher. Cleaning
	// up gracefully does not give us anything in this case. We just clean
	// up the sockets and let the application close.
	errDelete := deleteSocket(cfg.Dispatcher.ApplicationSocket)
	if errDelete != nil {
		log.Warn("Unable to delete socket when shutting down", "err", errDelete)
	}
	switch {
	case returnCode != 0:
		return returnCode
	case errDelete != nil:
		return 1
	default:
		return 0
	}
}

func setupBasic() error {
	md, err := toml.DecodeFile(env.ConfigFile(), &cfg)
	if err != nil {
		return serrors.WrapStr("failed to load config", err, "file", env.ConfigFile())
	}
	if len(md.Undecoded()) > 0 {
		return serrors.New("failed to load config: undecoded keys", "undecoded", md.Undecoded())
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		return serrors.WrapStr("failed to initialize logging", err)
	}
	prom.ExportElementID(cfg.Dispatcher.ID)
	return env.LogAppStarted("Dispatcher", cfg.Dispatcher.ID)
}

func RunDispatcher(deleteSocketFlag bool, applicationSocket string, socketFileMode os.FileMode,
	underlayPort int) error {

	if deleteSocketFlag {
		if err := deleteSocket(cfg.Dispatcher.ApplicationSocket); err != nil {
			return err
		}
	}
	dispatcher := &network.Dispatcher{
		UnderlaySocket:    fmt.Sprintf(":%d", underlayPort),
		ApplicationSocket: applicationSocket,
		SocketFileMode:    socketFileMode,
	}
	log.Debug("Dispatcher starting", "appSocket", applicationSocket, "underlayPort", underlayPort)
	return dispatcher.ListenAndServe()
}

func deleteSocket(socket string) error {
	if _, err := os.Stat(socket); err != nil {
		// File does not exist, or we can't read it, nothing to delete
		return nil
	}
	if err := os.Remove(socket); err != nil {
		return err
	}
	return nil
}

func waitForTeardown() int {
	select {
	case <-fatal.ShutdownChan():
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

func checkPerms() error {
	u, err := user.Current()
	if err != nil {
		return common.NewBasicError("Error retrieving user", err)
	}
	if u.Uid == "0" && !cfg.Features.AllowRunAsRoot {
		return serrors.New("Running as root is not allowed for security reasons")
	}
	return nil
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	var buf bytes.Buffer
	toml.NewEncoder(&buf).Encode(cfg)
	fmt.Fprint(w, buf.String())
}
