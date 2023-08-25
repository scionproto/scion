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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/dispatcher"
	"github.com/scionproto/scion/dispatcher/config"
	api "github.com/scionproto/scion/dispatcher/mgmtapi"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/service"
	"github.com/scionproto/scion/private/topology"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig:  &globalCfg,
		ShortName:   "SCION Dispatcher",
		RequiredIPs: requiredIPs,
		Main:        realMain,
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	path.StrictDecoding(false)
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      globalCfg.General.Topology(),
		Reload:    app.SIGHUPChannel(ctx),
		Validator: &topology.ControlValidator{ID: globalCfg.General.ID},
	})
	if err != nil {
		return err
	}

	var cleanup app.Cleanup
	g, errCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		return topo.Run(errCtx)
	})
	g.Go(func() error {
		defer log.HandlePanic()
		return RunDispatcher(
			topo,
			globalCfg.Dispatcher.UnderlayPort,
		)
	})

	// Initialise and start service management API endpoints.
	if globalCfg.API.Addr != "" {
		r := chi.NewRouter()
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins: []string{"*"},
		}))
		r.Get("/", api.ServeSpecInteractive)
		r.Get("/openapi.json", api.ServeSpecJSON)
		server := api.Server{
			Config:   service.NewConfigStatusPage(globalCfg).Handler,
			Info:     service.NewInfoStatusPage().Handler,
			LogLevel: service.NewLogLevelStatusPage().Handler,
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
				return serrors.WrapStr("serving service management API", err)
			}
			return nil
		})
	}

	// Start HTTP endpoints.
	statusPages := service.StatusPages{
		"info":      service.NewInfoStatusPage(),
		"config":    service.NewConfigStatusPage(globalCfg),
		"log/level": service.NewLogLevelStatusPage(),
	}
	if err := statusPages.Register(http.DefaultServeMux, globalCfg.Dispatcher.ID); err != nil {
		return serrors.WrapStr("registering status pages", err)
	}

	g.Go(func() error {
		defer log.HandlePanic()
		return globalCfg.Metrics.ServePrometheus(errCtx)
	})

	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})

	// XXX(lukedirtwalker): unfortunately the dispatcher can't be signalled to
	// be stopped, so we just exit manually if the context is done.
	select {
	case <-ctx.Done():
		return nil
	case <-errCtx.Done():
		return g.Wait()
	}
}

func RunDispatcher(topo *topology.Loader, underlayPort int) error {
	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", underlayPort))
	if err != nil {
		return err
	}
	log.Debug("Dispatcher starting", "localAddr", localAddr)
	return dispatcher.ListenAndServe(topo, localAddr)
}

func requiredIPs() ([]net.IP, error) {
	if globalCfg.Metrics.Prometheus == "" {
		return nil, nil
	}
	promAddr, err := net.ResolveTCPAddr("tcp", globalCfg.Metrics.Prometheus)
	if err != nil {
		return nil, serrors.WrapStr("parsing prometheus address", err)
	}
	return []net.IP{promAddr.IP}, nil
}
