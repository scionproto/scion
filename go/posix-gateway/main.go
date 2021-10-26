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
	"net"
	"net/http"
	_ "net/http/pprof"

	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	"github.com/scionproto/scion/go/pkg/gateway"
	"github.com/scionproto/scion/go/pkg/gateway/dataplane"
	"github.com/scionproto/scion/go/pkg/service"
	"github.com/scionproto/scion/go/posix-gateway/config"
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
	globalCfg.Metrics.StartPrometheus()

	reloadConfigTrigger := make(chan struct{})

	daemonService := &daemon.Service{
		Address: globalCfg.Daemon.Address,
	}
	daemon, err := daemonService.Connect(ctx)
	if err != nil {
		return serrors.WrapStr("connecting to daemon", err)
	}
	localIA, err := daemon.LocalIA(ctx)
	if err != nil {
		return serrors.WrapStr("retrieving local ISD-AS", err)
	}

	controlAddress, err := net.ResolveUDPAddr("udp", globalCfg.Gateway.CtrlAddr)
	if err != nil {
		return serrors.WrapStr("parsing control address", err)
	}
	if len(controlAddress.IP) == 0 {
		controlAddress.IP, err = addrutil.DefaultLocalIP(ctx, daemon)
		if err != nil {
			return serrors.WrapStr("determine default local IP", err)
		}
	}
	dataAddress, err := net.ResolveUDPAddr("udp", globalCfg.Gateway.DataAddr)
	if err != nil {
		return serrors.WrapStr("parsing data address", err)
	}
	if len(dataAddress.IP) == 0 {
		dataAddress.IP = controlAddress.IP
		dataAddress.Zone = controlAddress.Zone
	}
	probeAddress, err := net.ResolveUDPAddr("udp", globalCfg.Gateway.ProbeAddr)
	if err != nil {
		return serrors.WrapStr("parsing probe address", err)
	}
	if len(probeAddress.IP) == 0 {
		probeAddress.IP = controlAddress.IP
		probeAddress.Zone = controlAddress.Zone
	}
	httpPages := service.StatusPages{
		"info":           service.NewInfoStatusPage(),
		"config":         service.NewConfigStatusPage(globalCfg),
		"digests/config": service.NewConfigDigestStatusPage(&globalCfg),
		"log/level":      service.NewLogLevelStatusPage(),
	}
	routingTable := &dataplane.AtomicRoutingTable{}
	gw := &gateway.Gateway{
		ID:                       globalCfg.Gateway.ID,
		TrafficPolicyFile:        globalCfg.Gateway.TrafficPolicy,
		RoutingPolicyFile:        globalCfg.Gateway.IPRoutingPolicy,
		ControlServerAddr:        controlAddress,
		ControlClientIP:          controlAddress.IP,
		ServiceDiscoveryClientIP: controlAddress.IP,
		PathMonitorIP:            controlAddress.IP,
		ProbeServerAddr:          probeAddress,
		ProbeClientIP:            controlAddress.IP,
		DataServerAddr:           dataAddress,
		DataClientIP:             dataAddress.IP,
		Dispatcher:               reliable.NewDispatcher(""),
		Daemon:                   daemon,
		RouteSourceIPv4:          globalCfg.Tunnel.SrcIPv4,
		RouteSourceIPv6:          globalCfg.Tunnel.SrcIPv6,
		TunnelName:               globalCfg.Tunnel.Name,
		RoutingTableReader:       routingTable,
		RoutingTableSwapper:      routingTable,
		ConfigReloadTrigger:      reloadConfigTrigger,
		HTTPEndpoints:            httpPages,
		HTTPServeMux:             http.DefaultServeMux,
		Logger:                   log.New(),
		Metrics:                  gateway.NewMetrics(localIA),
	}

	errs := make(chan error, 1)
	go func() {
		defer log.HandlePanic()
		if err := gw.Run(ctx); err != nil {
			errs <- err
		}
	}()

	env.SetupEnv(func() {
		reloadConfigTrigger <- struct{}{}
	})

	select {
	case err := <-errs:
		return err
	case <-fatal.ShutdownChan():
		return nil
	case <-fatal.FatalChan():
		return serrors.New("received fatal error")
	}
}
