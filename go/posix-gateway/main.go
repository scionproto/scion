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
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"

	"github.com/syndtr/gocapability/capability"
	"github.com/vishvananda/netlink"

	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	"github.com/scionproto/scion/go/pkg/gateway"
	"github.com/scionproto/scion/go/pkg/gateway/xnet"
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

func realMain() error {
	globalCfg.Metrics.StartPrometheus()

	reloadConfigTrigger := make(chan struct{})

	tunnelLink, tunnelIO, err := initTunnel(globalCfg)
	if err != nil {
		return serrors.WrapStr("initializing TUN device", err)
	}
	log.Debug("Tunnel device initialized", "dev", globalCfg.Tunnel.Name)

	if !gateway.ExperimentalExportMainRT() {
		if err := dropNetworkCapabilities(); err != nil {
			return serrors.WrapStr("dropping capabilities", err)
		}
		log.Debug("Network capabilities dropped (dropped CAP_NET_ADMIN)")
	}

	daemonService := &daemon.Service{
		Address: globalCfg.Daemon.Address,
	}
	daemon, err := daemonService.Connect(context.TODO())
	if err != nil {
		return serrors.WrapStr("connecting to daemon", err)
	}

	controlAddress, err := net.ResolveUDPAddr("udp", globalCfg.Gateway.CtrlAddr)
	if err != nil {
		return serrors.WrapStr("parsing control address", err)
	}
	if len(controlAddress.IP) == 0 {
		controlAddress.IP, err = addrutil.DefaultLocalIP(context.Background(), daemon)
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
	httpPages := service.StatusPages{
		"info":      service.NewInfoHandler(),
		"config":    service.NewConfigHandler(globalCfg),
		"log/level": log.ConsoleLevel.ServeHTTP,
	}
	gw := &gateway.Gateway{
		TrafficPolicyFile:        globalCfg.Gateway.TrafficPolicy,
		RoutingPolicyFile:        globalCfg.Gateway.IPRoutingPolicy,
		ControlServerAddr:        controlAddress,
		ControlClientIP:          controlAddress.IP,
		ServiceDiscoveryClientIP: controlAddress.IP,
		PathMonitorIP:            controlAddress.IP,
		ProbeServerAddr:          &net.UDPAddr{IP: controlAddress.IP, Port: 30856},
		ProbeClientIP:            controlAddress.IP,
		DataServerAddr:           dataAddress,
		DataClientIP:             dataAddress.IP,
		Dispatcher:               reliable.NewDispatcher(""),
		Daemon:                   daemon,
		InternalDevice:           tunnelIO,
		RouteDevice:              tunnelLink,
		RouteSource:              dataAddress.IP,
		ConfigReloadTrigger:      reloadConfigTrigger,
		HTTPEndpoints:            httpPages,
		HTTPServeMux:             http.DefaultServeMux,
		Logger:                   log.New(),
		Metrics:                  gateway.NewMetrics(),
	}

	errs := make(chan error, 1)
	go func() {
		defer log.HandlePanic()
		if err := gw.Run(); err != nil {
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

func initTunnel(cfg config.Config) (netlink.Link, io.ReadWriteCloser, error) {
	tunLink, tunIO, err := xnet.ConnectTun(cfg.Tunnel.Name)
	if err != nil {
		return nil, nil, err
	}

	if !gateway.ExperimentalExportMainRT() {
		defaultV4Net := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, net.IPv4len*8)}
		err = xnet.AddRoute(cfg.Tunnel.RoutingTableID, tunLink, defaultV4Net, nil)
		if err != nil {
			return nil, nil,
				serrors.WrapStr("adding default IPv4 route to gateway routing table", err)
		}

		// FIXME(scrye): Uncomment this when we start testing IPv6.
		// defaultV6Net := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, net.IPv6len*8)}
		// err = xnet.AddRoute(cfg.Tunnel.RoutingTableID, tunLink, DefaultV6Net, nil)
		// if err != nil {
		// 	return nil, nil,
		// serrors.WrapStr("adding default IPv6 route to gateway routing table", err)
		// }
	}
	return tunLink, tunIO, nil
}

func dropNetworkCapabilities() error {
	caps, err := capability.NewPid(0)
	if err != nil {
		return serrors.WrapStr("retrieving capabilities", err)
	}
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)
	return nil
}
