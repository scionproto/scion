// Copyright 2020 Anapaya Systems
// Copyright 2025 SCION Association
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

// Router is a SCION border router implementation as a system process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"sync/atomic"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/service"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/config"
	"github.com/scionproto/scion/router/control"
	api "github.com/scionproto/scion/router/mgmtapi"
	_ "github.com/scionproto/scion/router/underlayproviders/udpip"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		ApplicationBase: launcher.ApplicationBase{
			TOMLConfig: &globalCfg,
			ShortName:  "SCION Router",
			Main:       realMain,
		},
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	topoMetrics := topologyMetrics()
	validator := &topology.RouterValidator{ID: globalCfg.General.ID}
	topo, err := loadTopology(validator, nil, topoMetrics)
	if err != nil {
		return serrors.Wrap("loading topology", err)
	}
	var currentTopo atomic.Pointer[topology.Topology]
	currentTopo.Store(&topo)
	controlConfig, err := control.NewConfig(
		globalCfg.General.ID, topo, globalCfg.General.ConfigDir,
	)
	if err != nil {
		return err
	}
	g, errCtx := errgroup.WithContext(ctx)
	dp := router.NewConnector(globalCfg.Router, globalCfg.Features)
	iaCtx := &control.IACtx{
		Config: controlConfig,
		DP:     dp,
	}
	if err := iaCtx.Configure(); err != nil {
		return serrors.Wrap("configuring dataplane", err)
	}
	reload := app.SIGHUPChannel(errCtx)
	g.Go(func() error {
		defer log.HandlePanic()
		for {
			select {
			case <-reload:
				old := (*currentTopo.Load()).Writable()
				topo, err := loadTopology(validator, old, topoMetrics)
				if err != nil {
					log.Error("Failed to reload topology file",
						"file", globalCfg.General.Topology(), "err", err)
					continue
				}
				log.Info("Reloaded topology")
				currentTopo.Store(&topo)
				if err := iaCtx.UpdateTopology(topo); err != nil {
					log.Error("Failed to apply the reloaded topology", "err", err)
				}
			case <-errCtx.Done():
				return nil
			}
		}
	})
	statusPages := service.StatusPages{
		"info":      service.NewInfoStatusPage(),
		"config":    service.NewConfigStatusPage(globalCfg),
		"log/level": service.NewLogLevelStatusPage(),
		"topology":  topologyHandler(&currentTopo),
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
		if err := dp.DataPlane.Run(errCtx); err != nil {
			return serrors.Wrap("running dataplane", err)
		}
		return nil
	})

	return g.Wait()
}

// loadTopology reads the topology file and validates it against old, the topology in use.
// old is nil at startup.
// The router doesn't use [topology.Loader], which offers only parts of the topology.
func loadTopology(
	v topology.Validator, old *topology.RWTopology, m topology.LoaderMetrics,
) (topology.Topology, error) {
	topo, err := topology.FromJSONFile(globalCfg.General.Topology())
	if err != nil {
		metrics.CounterInc(m.ReadErrors)
		return nil, err
	}
	if err := v.Validate(topo.Writable(), old); err != nil {
		metrics.CounterInc(m.ValidationErrors)
		return nil, serrors.Wrap("validating topology", err)
	}
	metrics.CounterInc(m.Updates)
	metrics.GaugeSetCurrentTime(m.LastUpdate)
	return topo, nil
}

// topologyMetrics returns the metrics that the control service
// and the daemon have for their topology loaders.
func topologyMetrics() topology.LoaderMetrics {
	updates := prom.NewCounterVec("", "",
		"topology_updates_total",
		"The total number of updates.",
		[]string{prom.LabelResult},
	)
	return topology.LoaderMetrics{
		ValidationErrors: metrics.NewPromCounter(updates).
			With(prom.LabelResult, "err_validate"),
		ReadErrors: metrics.NewPromCounter(updates).
			With(prom.LabelResult, "err_read"),
		LastUpdate: metrics.NewPromGauge(
			prom.NewGaugeVec("", "",
				"topology_last_update_time",
				"Timestamp of the last successful update.",
				[]string{},
			),
		),
		Updates: metrics.NewPromCounter(updates).With(prom.LabelResult, prom.Success),
	}
}

func topologyHandler(topo *atomic.Pointer[topology.Topology]) service.StatusPage {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		bytes, err := json.MarshalIndent(*topo.Load(), "", "    ")
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
