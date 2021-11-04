// Copyright 2021 Anapaya Systems
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

package fake

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/routemgr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/pkg/gateway"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

// Gateway is a fake gateway. It uses the configurations provided by the
// configuration updates channel to configure a dataplane.
type Gateway struct {
	// TunnelName is the device name for the Linux global tunnel device.
	TunnelName string

	// RoutingTableReader is used for routing the packets.
	RoutingTableReader control.RoutingTableReader
	// RoutingTableSwapper permits the concurrency-safe swapping of an entire
	// routing table in the data-plane. When the session builder creates a new
	// control-plane engine, it creates a fresh routing table. Once the engine
	// is ready, the fresh routing table is swapped in place of the old one. It
	// must not be nil.
	RoutingTableSwapper control.RoutingTableSwapper
	// DeviceManager is used to create devices for remote IAs.
	DeviceManager control.DeviceManager

	// DataPlaneRunner is an interface to start different data plane components.
	DataPlaneRunner gateway.DataPlaneRunner

	// DataServerAddr is the address for encapsulated data traffic received from other gateways.
	DataServerAddr *net.UDPAddr
	// DataClientIP is the IP from which encapsulated data traffic is sent to other gateways.
	DataClientIP net.IP

	// Dispatcher is the API of the SCION Dispatcher on the local host.
	Dispatcher reliable.Dispatcher

	// Daemon is the API of the SCION Daemon.
	Daemon daemon.Connector

	// ConfigurationUpdates is the channel where new configurations are
	// published.
	ConfigurationUpdates <-chan *Config

	// Metrics are the metrics exported by the gateway.
	Metrics *gateway.Metrics

	// DummyRouting disables the publishing of routes to the Linux kernel.
	DummyRouting bool

	// ReportingCollector is used by some data-plane implementations to report additional
	// data about internals.
	ReportingCollector interface{}

	sessions map[int]control.DataplaneSession
	handles  []control.DeviceHandle
}

// Run runs the fake gateway, it reads configurations from the configuration
// channel.
func (g *Gateway) Run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	routePublisherFactory := createRouteManager(ctx, g.DeviceManager, g.DummyRouting)

	localIA, err := g.Daemon.LocalIA(ctx)
	if err != nil {
		return serrors.WrapStr("unable to learn local ISD-AS number", err)
	}

	var (
		scmpErrors             metrics.Counter
		scionPacketConnMetrics snet.SCIONPacketConnMetrics
		scionNetworkMetrics    snet.SCIONNetworkMetrics
	)
	if g.Metrics != nil {
		scmpErrors = g.Metrics.SCMPErrors
		scionPacketConnMetrics = g.Metrics.SCIONPacketConnMetrics
		scionNetworkMetrics = g.Metrics.SCIONNetworkMetrics
	}
	scionNetwork := &snet.SCIONNetwork{
		LocalIA: localIA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: reliable.NewDispatcher(""),
			SCMPHandler: &snet.DefaultSCMPHandler{
				SCMPErrors: scmpErrors,
			},
			SCIONPacketConnMetrics: scionPacketConnMetrics,
		},
		Metrics: scionNetworkMetrics,
	}

	logger.Info("Starting ingress", "local_isd_as", localIA)
	if err := g.DataPlaneRunner.StartIngress(scionNetwork, g.DataServerAddr,
		g.DeviceManager, nil); err != nil {

		return err
	}

	dataPlaneSessionFactory := g.DataPlaneRunner.NewDataPlaneSessionFactory(
		scionNetwork,
		g.DataClientIP,
		g.Metrics,
		g.ReportingCollector,
	)
	routingTableFactory := g.DataPlaneRunner.NewRoutingTableFactory()

	for c := range g.ConfigurationUpdates {
		logger.Debug("New forwarding engine configuration found", "c", c)
		routingTable, err := routingTableFactory.New(c.Chains)
		if err != nil {
			return serrors.WrapStr("creating routing table", err)
		}

		rt := control.NewPublishingRoutingTable(c.Chains, routingTable,
			routePublisherFactory.NewPublisher(), net.IP{}, net.IP{}, net.IP{})
		newSessions := make(map[int]control.DataplaneSession, len(c.Sessions))
		newHandles := make([]control.DeviceHandle, 0)
		for _, s := range c.Sessions {
			handle, err := g.DeviceManager.Get(context.Background(), s.RemoteIA)
			if err != nil {
				return serrors.WrapStr("getting handle", err)
			}
			newHandles = append(newHandles, handle)

			newSessions[s.ID] = dataPlaneSessionFactory.
				New(uint8(s.ID), s.PolicyID, s.RemoteIA, s.RemoteAddr)
			if err := newSessions[s.ID].SetPaths(s.Paths); err != nil {
				return err
			}
			if s.IsUp {
				if err := rt.SetSession(s.ID, newSessions[s.ID]); err != nil {
					return serrors.WrapStr("adding route", err, "session_id", s.ID)
				}
			}
		}
		g.RoutingTableSwapper.SetRoutingTable(rt)
		for _, sess := range g.sessions {
			sess.Close()
		}
		for _, handle := range g.handles {
			if err := handle.Close(); err != nil {
				// An error here might mean that the operator manually tampered with
				// the device. Depending on the new state of the device, we might
				// be able to continue running, so we don't return with an error.
				logger.Info("Encountered error when closing device handle", "err", err)
			}
		}
		g.sessions = newSessions
		g.handles = newHandles
	}
	return nil
}

func createRouteManager(ctx context.Context, deviceManager control.DeviceManager,
	dummyRouting bool) control.PublisherFactory {

	if dummyRouting {
		return &routemgr.Dummy{}
	}

	linux := &routemgr.Linux{DeviceManager: deviceManager}
	go func() {
		defer log.HandlePanic()
		linux.Run(ctx)
	}()

	return linux
}

// Daemon implements only the parts of the SCION Daemon API that the fake
// Gateway requires.
type Daemon struct {
	// Connector is embedded but never initialized s.t. panics are raised
	// on all API calls except overridden ones.
	daemon.Connector

	IA addr.IA
}

func (d *Daemon) LocalIA(_ context.Context) (addr.IA, error) {
	return d.IA, nil
}
