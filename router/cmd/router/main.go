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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/service"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/config"
	"github.com/scionproto/scion/router/control"
	api "github.com/scionproto/scion/router/mgmtapi"
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

func realMain(ctx context.Context) error {
	controlConfig, err := loadControlConfig()
	if err != nil {
		return err
	}
	g, errCtx := errgroup.WithContext(ctx)
	metrics := router.NewMetrics()

	dp := &router.Connector{
		DataPlane: router.DataPlane{
			Metrics:                        metrics,
			ExperimentalSCMPAuthentication: globalCfg.Features.ExperimentalSCMPAuthentication,
		},
		ReceiveBufferSize:   globalCfg.Router.ReceiveBufferSize,
		SendBufferSize:      globalCfg.Router.SendBufferSize,
		BFD:                 globalCfg.Router.BFD,
		DispatchedPortStart: globalCfg.Router.DispatchedPortStart,
		DispatchedPortEnd:   globalCfg.Router.DispatchedPortEnd,
	}
	iaCtx := &control.IACtx{
		Config: controlConfig,
		DP:     dp,
	}
	if err := iaCtx.Configure(); err != nil {
		return serrors.Wrap("configuring dataplane", err)
	}
	statusPages := service.StatusPages{
		"info":      service.NewInfoStatusPage(),
		"config":    service.NewConfigStatusPage(globalCfg),
		"log/level": service.NewLogLevelStatusPage(),
		"topology":  topologyHandler(iaCtx.Config.Topo),
	}
	if err := statusPages.Register(http.DefaultServeMux, globalCfg.General.ID); err != nil {
		return err
	}

	var cleanup app.Cleanup
	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})

	// Initialize and start service management API.
	if globalCfg.API.Addr != "" {
		r := chi.NewRouter()
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins: []string{"*"},
		}))
		r.Get("/", api.ServeSpecInteractive)
		r.Get("/openapi.json", api.ServeSpecJSON)
		server := api.Server{
			Config:    service.NewConfigStatusPage(globalCfg).Handler,
			Info:      service.NewInfoStatusPage().Handler,
			LogLevel:  service.NewLogLevelStatusPage().Handler,
			Dataplane: dp,
		}
		log.Info("Exposing API", "addr", globalCfg.API.Addr)
		h := api.HandlerFromMuxWithBaseURL(&server, r, "/api/v1")
		mgmtServer := &http.Server{
			Addr:    globalCfg.API.Addr,
			Handler: h,
		}
		cleanup.Add(mgmtServer.Close)
		g.Go(func() error {
			defer log.HandlePanic()
			err := mgmtServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return serrors.Wrap("serving service management API", err)
			}
			return nil
		})
	}
	g.Go(func() error {
		defer log.HandlePanic()
		return globalCfg.Metrics.ServePrometheus(errCtx)
	})
	g.Go(func() error {
		defer log.HandlePanic()
		runConfig := &router.RunConfig{
			NumProcessors:         globalCfg.Router.NumProcessors,
			NumSlowPathProcessors: globalCfg.Router.NumSlowPathProcessors,
			BatchSize:             globalCfg.Router.BatchSize,
		}
		if err := dp.DataPlane.Run(errCtx, runConfig); err != nil {
			return serrors.Wrap("running dataplane", err)
		}
		return nil
	})

	return g.Wait()
}

func loadControlConfig() (*control.Config, error) {
	newConf, err := control.LoadConfig(globalCfg.General.ID, globalCfg.General.ConfigDir)
	if err != nil {
		return nil, serrors.Wrap("loading topology", err)
	}
	return newConf, nil
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
	return service.StatusPage{
		Info:    "SCION topology",
		Handler: handler,
	}
}
