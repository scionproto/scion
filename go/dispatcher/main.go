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
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/scionproto/scion/go/dispatcher/config"
	"github.com/scionproto/scion/go/dispatcher/network"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	"github.com/scionproto/scion/go/pkg/service"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "SCION Dispatcher",
		Main:       realMain,
	}
	application.Run()
}

func realMain() error {
	if err := util.CreateParentDirs(globalCfg.Dispatcher.ApplicationSocket); err != nil {
		return serrors.WrapStr("creating directory tree for socket", err)
	}

	path.StrictDecoding(false)

	go func() {
		defer log.HandlePanic()
		err := RunDispatcher(
			globalCfg.Dispatcher.DeleteSocket,
			globalCfg.Dispatcher.ApplicationSocket,
			os.FileMode(globalCfg.Dispatcher.SocketFileMode),
			globalCfg.Dispatcher.UnderlayPort,
		)
		if err != nil {
			// FIXME(scrye): properly clean this up.
			fatal.Fatal(err)
		}
	}()

	// Start HTTP endpoints.
	statusPages := service.StatusPages{
		"info":      service.NewInfoHandler(),
		"config":    service.NewConfigHandler(globalCfg),
		"log/level": log.ConsoleLevel.ServeHTTP,
	}
	if err := statusPages.Register(http.DefaultServeMux, globalCfg.Dispatcher.ID); err != nil {
		return serrors.WrapStr("registering status pages", err)
	}
	globalCfg.Metrics.StartPrometheus()

	defer deleteSocket(globalCfg.Dispatcher.ApplicationSocket)

	returnCode := waitForTeardown()
	if returnCode != 0 {
		return serrors.New("fatal teardown exited with non-zero code", "code", returnCode)
	}
	return nil
}

func RunDispatcher(deleteSocketFlag bool, applicationSocket string, socketFileMode os.FileMode,
	underlayPort int) error {

	if deleteSocketFlag {
		if err := deleteSocket(globalCfg.Dispatcher.ApplicationSocket); err != nil {
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
