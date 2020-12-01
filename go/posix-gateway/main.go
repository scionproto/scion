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
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/syndtr/gocapability/capability"
	"github.com/vishvananda/netlink"

	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/pkg/gateway"
	"github.com/scionproto/scion/go/pkg/gateway/xnet"
	"github.com/scionproto/scion/go/pkg/service"
	"github.com/scionproto/scion/go/posix-gateway/config"
)

func main() {
	var flags struct {
		config string
	}
	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:           executable,
		Short:         "SCION IP gateway",
		Example:       "  " + executable + " --config gateway.toml",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(flags.config)
		},
	}
	cmd.AddCommand(
		command.NewCompletion(cmd),
		command.NewSample(cmd,
			command.NewSampleConfig(&config.Config{}),
		),
		command.NewVersion(cmd),
	)
	cmd.Flags().StringVar(&flags.config, "config", "", "Configuration file (required)")
	cmd.MarkFlagRequired("config")
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run(file string) error {
	fatal.Init()
	cfg, err := setupBasic(file)
	if err != nil {
		return err
	}
	defer log.Flush()
	defer env.LogAppStopped("Gateway", cfg.Gateway.ID)
	defer log.HandlePanic()
	if err := cfg.Validate(); err != nil {
		return serrors.WrapStr("validating config", err)
	}
	cfg.Metrics.StartPrometheus()

	reloadConfigTrigger := make(chan struct{})

	tunnelLink, tunnelIO, err := initTunnel(cfg)
	if err != nil {
		return serrors.WrapStr("initializing TUN device", err)
	}
	log.Debug("Tunnel device initialized", "dev", cfg.Tunnel.Name)

	if !gateway.ExperimentalExportMainRT() {
		if err := dropNetworkCapabilities(); err != nil {
			return serrors.WrapStr("dropping capabilities", err)
		}
		log.Debug("Network capabilities dropped (dropped CAP_NET_ADMIN)")
	}

	daemonService := &sciond.Service{
		Address: cfg.Daemon.Address,
	}
	daemon, err := daemonService.Connect(context.TODO())
	if err != nil {
		return serrors.WrapStr("connecting to daemon", err)
	}

	controlAddress, err := net.ResolveUDPAddr("udp", cfg.Gateway.CtrlAddr)
	if err != nil {
		return serrors.WrapStr("parsing control address", err)
	}
	if len(controlAddress.IP) == 0 {
		controlAddress.IP, err = addrutil.DefaultLocalIP(context.Background(), daemon)
		if err != nil {
			return serrors.WrapStr("determine default local IP", err)
		}
	}
	dataAddress, err := net.ResolveUDPAddr("udp", cfg.Gateway.DataAddr)
	if err != nil {
		return serrors.WrapStr("parsing data address", err)
	}
	if len(dataAddress.IP) == 0 {
		dataAddress.IP = controlAddress.IP
		dataAddress.Zone = controlAddress.Zone
	}
	httpPages := service.StatusPages{
		"info":      service.NewInfoHandler(),
		"config":    service.NewConfigHandler(cfg),
		"log/level": log.ConsoleLevel.ServeHTTP,
	}
	gw := &gateway.Gateway{
		TrafficPolicyFile:        cfg.Gateway.TrafficPolicy,
		RoutingPolicyFile:        cfg.Gateway.IPRoutingPolicy,
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

// setupBasic loads the config from file and initializes logging.
func setupBasic(file string) (config.Config, error) {
	var cfg config.Config
	if err := libconfig.LoadFile(file, &cfg); err != nil {
		return config.Config{}, serrors.WrapStr("loading config from file", err, "file", file)
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		return config.Config{}, serrors.WrapStr("initialize logging", err)
	}
	prom.ExportElementID(cfg.Gateway.ID)
	if err := env.LogAppStarted("Gateway", cfg.Gateway.ID); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
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
