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
	"errors"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/gateway"
	"github.com/scionproto/scion/gateway/config"
	"github.com/scionproto/scion/gateway/dataplane"
	api "github.com/scionproto/scion/gateway/mgmtapi"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/service"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "SCION IP Gateway",
		Main:       realMain,
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	daemonService := &daemon.Service{
		Address: globalCfg.Daemon.Address,
	}
	daemon, err := daemonService.Connect(ctx)
	if err != nil {
		return serrors.Wrap("connecting to daemon", err)
	}
	defer daemon.Close()
	localIA, err := daemon.LocalIA(ctx)
	if err != nil {
		return serrors.Wrap("retrieving local ISD-AS", err)
	}

	controlAddress, err := net.ResolveUDPAddr("udp", globalCfg.Gateway.CtrlAddr)
	if err != nil {
		return serrors.Wrap("parsing control address", err)
	}
	if len(controlAddress.IP) == 0 {
		controlAddress.IP, err = addrutil.DefaultLocalIP(ctx, daemon)
		if err != nil {
			return serrors.Wrap("determine default local IP", err)
		}
	}
	controlAddressIP, ok := netip.AddrFromSlice(controlAddress.IP)
	if !ok {
		return serrors.New("invalid IP address", "control", controlAddress.IP)
	}
	dataAddress, err := net.ResolveUDPAddr("udp", globalCfg.Gateway.DataAddr)
	if err != nil {
		return serrors.Wrap("parsing data address", err)
	}
	if len(dataAddress.IP) == 0 {
		dataAddress.IP = controlAddress.IP
		dataAddress.Zone = controlAddress.Zone
	}
	probeAddress, err := net.ResolveUDPAddr("udp", globalCfg.Gateway.ProbeAddr)
	if err != nil {
		return serrors.Wrap("parsing probe address", err)
	}
	if len(probeAddress.IP) == 0 {
		probeAddress.IP = controlAddress.IP
		probeAddress.Zone = controlAddress.Zone
	}
	var cleanup app.Cleanup
	g, errCtx := errgroup.WithContext(ctx)
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
		defer mgmtServer.Close()
		g.Go(func() error {
			defer log.HandlePanic()
			err := mgmtServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return serrors.Wrap("serving service management API", err)
			}
			return nil
		})
		cleanup.Add(mgmtServer.Close)
	}

	httpPages := service.StatusPages{
		"info":      service.NewInfoStatusPage(),
		"config":    service.NewConfigStatusPage(globalCfg),
		"log/level": service.NewLogLevelStatusPage(),
	}
	routingTable := &dataplane.AtomicRoutingTable{}
	gw := &gateway.Gateway{
		ID:                       globalCfg.Gateway.ID,
		TrafficPolicyFile:        globalCfg.Gateway.TrafficPolicy,
		RoutingPolicyFile:        globalCfg.Gateway.IPRoutingPolicy,
		ControlServerAddr:        controlAddress,
		ControlClientIP:          controlAddress.IP,
		ServiceDiscoveryClientIP: controlAddress.IP,
		PathMonitorIP:            controlAddressIP,
		ProbeServerAddr:          probeAddress,
		ProbeClientIP:            controlAddress.IP,
		DataServerAddr:           dataAddress,
		DataClientIP:             dataAddress.IP,
		Daemon:                   daemon,
		RouteSourceIPv4:          globalCfg.Tunnel.SrcIPv4,
		RouteSourceIPv6:          globalCfg.Tunnel.SrcIPv6,
		TunnelName:               globalCfg.Tunnel.Name,
		RoutingTableReader:       routingTable,
		RoutingTableSwapper:      routingTable,
		ConfigReloadTrigger:      app.SIGHUPChannel(ctx),
		HTTPEndpoints:            httpPages,
		HTTPServeMux:             http.DefaultServeMux,
		Metrics:                  gateway.NewMetrics(localIA),
	}

	g.Go(func() error {
		defer log.HandlePanic()
		return globalCfg.Metrics.ServePrometheus(errCtx)
	})
	g.Go(func() error {
		defer log.HandlePanic()
		return gw.Run(errCtx)
	})
	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})

	return g.Wait()
}
