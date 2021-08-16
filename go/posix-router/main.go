// Copyright 2020 Anapaya Systems
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
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"sync"

	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	"github.com/scionproto/scion/go/pkg/router"
	"github.com/scionproto/scion/go/pkg/router/config"
	"github.com/scionproto/scion/go/pkg/router/control"
	"github.com/scionproto/scion/go/pkg/service"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "SCION Router",
		Main:       realMain,
	}
	application.Run()
}

func realMain() error {
	controlConfig, err := loadControlConfig()
	if err != nil {
		return err
	}
	metrics := router.NewMetrics()
	stop := make(chan struct{})
	wg := new(sync.WaitGroup)
	dp := &router.Connector{
		DataPlane: router.DataPlane{
			Metrics: metrics,
		},
	}
	iaCtx := &control.IACtx{
		Config: controlConfig,
		DP:     dp,
		Stop:   stop,
	}
	if err := iaCtx.Start(wg); err != nil {
		return serrors.WrapStr("starting dataplane", err)
	}
	if err := setupHTTPHandlers(iaCtx.Config.Topo); err != nil {
		return serrors.WrapStr("starting HTTP endpoints", err)
	}

	errs := make(chan error, 1)
	go func() {
		defer log.HandlePanic()
		if err := dp.DataPlane.Run(); err != nil {
			errs <- serrors.WrapStr("running dataplane", err)
			return
		}
		errs <- serrors.New("dataplane stopped unexpectedly")
	}()

	select {
	case err := <-errs:
		close(stop)
		wg.Wait()
		return err
	case <-fatal.ShutdownChan():
		// Whenever we receive a SIGINT or SIGTERM we exit without an error.
		// Deferred shutdowns for all running servers run now.
		close(stop)
		wg.Wait()
		return nil
	case <-fatal.FatalChan():
		return serrors.New("shutdown on error")
	}
}

func loadControlConfig() (*control.Config, error) {
	newConf, err := control.LoadConfig(globalCfg.General.ID, globalCfg.General.ConfigDir)
	if err != nil {
		return nil, serrors.WrapStr("loading topology", err)
	}
	return newConf, nil
}

func setupHTTPHandlers(topo topology.Topology) error {
	statusPages := service.StatusPages{
		"info":             service.NewInfoStatusPage(),
		"config":           service.NewConfigStatusPage(globalCfg),
		"log/level":        service.NewLogLevelStatusPage(),
		"topology":         topologyHandler(topo),
		"digests/config":   service.NewConfigDigestStatusPage(&globalCfg),
		"digests/topology": topologyDigestHandler(topo),
	}
	if err := statusPages.Register(http.DefaultServeMux, globalCfg.General.ID); err != nil {
		return err
	}
	globalCfg.Metrics.StartPrometheus()
	return nil
}

func topologyHandler(topo topology.Topology) service.StatusPage {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		bytes, err := json.MarshalIndent(topo, "", "    ")
		if err != nil {
			http.Error(w, "Unable to marshal topology", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(bytes)+"\n")
	}
	return service.StatusPage{Handler: handler}
}

func topologyDigestHandler(topo topology.Topology) service.StatusPage {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		digest, err := topology.Digest(topo)
		if err != nil {
			http.Error(w, "Unable to calculate digest", http.StatusInternalServerError)
			return
		}
		res := struct {
			Digest []byte `json:"digest"`
		}{
			Digest: digest,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		if err := enc.Encode(res); err != nil {
			http.Error(w, "Unable to marshal response", http.StatusInternalServerError)
			return
		}
	}
	return service.StatusPage{Handler: handler}
}
