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

package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	quic "github.com/quic-go/quic-go"
	"google.golang.org/grpc"

	"github.com/scionproto/scion/gateway/control"
	controlgrpc "github.com/scionproto/scion/gateway/control/grpc"
	"github.com/scionproto/scion/gateway/dataplane"
	"github.com/scionproto/scion/gateway/pathhealth"
	"github.com/scionproto/scion/gateway/pathhealth/policies"
	"github.com/scionproto/scion/gateway/routemgr"
	"github.com/scionproto/scion/gateway/routing"
	"github.com/scionproto/scion/gateway/xnet"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	gatewaypb "github.com/scionproto/scion/pkg/proto/gateway"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	infraenv "github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/service"
	"github.com/scionproto/scion/private/svc"
)

const (
	// swapDelay is the delay between instantiation a new gateway config in the
	// control plane and pushing it to the dataplane. It's needed to make the probes
	// pass through the new paths. Probes are send every 500ms, 3 are needed to
	// make the path "alive", add some transmission delay - 2 seconds should be fine.
	swapDelay = 2 * time.Second
)

type DataplaneSessionFactory struct {
	PacketConnFactory  PacketConnFactory
	PathStatsPublisher dataplane.PathStatsPublisher
	Metrics            dataplane.SessionMetrics
}

func (dpf DataplaneSessionFactory) New(id uint8, policyID int,
	remoteIA addr.IA, remoteAddr net.Addr) control.DataplaneSession {

	conn, err := dpf.PacketConnFactory.New()
	if err != nil {
		panic(err)
	}
	labels := []string{"remote_isd_as", remoteIA.String(), "policy_id", strconv.Itoa(policyID)}
	metrics := dataplane.SessionMetrics{
		IPPktBytesSent:     metrics.CounterWith(dpf.Metrics.IPPktBytesSent, labels...),
		IPPktsSent:         metrics.CounterWith(dpf.Metrics.IPPktsSent, labels...),
		FrameBytesSent:     metrics.CounterWith(dpf.Metrics.FrameBytesSent, labels...),
		FramesSent:         metrics.CounterWith(dpf.Metrics.FramesSent, labels...),
		SendExternalErrors: dpf.Metrics.SendExternalErrors,
	}
	sess := &dataplane.Session{
		SessionID:          id,
		GatewayAddr:        *remoteAddr.(*net.UDPAddr),
		DataPlaneConn:      conn,
		PathStatsPublisher: dpf.PathStatsPublisher,
		Metrics:            metrics,
	}
	return sess
}

type PacketConnFactory struct {
	Network *snet.SCIONNetwork
	Addr    *net.UDPAddr
}

func (pcf PacketConnFactory) New() (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := pcf.Network.Listen(ctx, "udp", pcf.Addr)
	if err != nil {
		return nil, serrors.Wrap("creating packet conn", err)
	}
	return conn, nil
}

type RoutingTableFactory struct {
	RoutePublisherFactory control.PublisherFactory
}

func (rtf RoutingTableFactory) New(
	routingChains []*control.RoutingChain,
) (control.RoutingTable, error) {

	return dataplane.NewRoutingTable(routingChains), nil
}

// SelectAdvertisedRoutes computes the networks that should be advertised
// depending on the state of the last published routing policy file.
type SelectAdvertisedRoutes struct {
	ConfigPublisher *control.ConfigPublisher
}

func (a *SelectAdvertisedRoutes) AdvertiseList(from, to addr.IA) ([]netip.Prefix, error) {
	return routing.AdvertiseList(a.ConfigPublisher.RoutingPolicy(), from, to)
}

type RoutingPolicyPublisherAdapter struct {
	*control.ConfigPublisher
}

func (cp RoutingPolicyPublisherAdapter) PublishRoutingPolicy(rp *routing.Policy) {
	cp.ConfigPublisher.Publish(nil, rp)
}

type Gateway struct {
	// ID is the ID of this gateway.
	ID string
	// TrafficPolicyFile holds the location of the traffic policy file.
	TrafficPolicyFile string
	// RoutingPolicyFile holds the location of the routing policy file.
	RoutingPolicyFile string

	// ControlClientIP is the IP for network prefix discovery.
	ControlClientIP net.IP
	// ControlServerAddr is the address of the local gRPC server serving prefix
	// discovery requests. The server runs on the UDP/SCION + QUIC stack.
	ControlServerAddr *net.UDPAddr

	// ServiceDiscoveryClientIP is the IP for SCION Service Discovery UDP packets.
	ServiceDiscoveryClientIP net.IP

	// PathMonitorIP is the IP that should be used for path monitoring SCMP traceroute traffic.
	PathMonitorIP netip.Addr
	// ProbeServerAddr is the address for the probe server. The probe server replies
	// to probe traffic from other gateways.
	ProbeServerAddr *net.UDPAddr
	// ProbeClientIP is the IP from which local probes will be sent out.
	ProbeClientIP net.IP

	// DataServerAddr is the address for encapsulated data traffic received from other gateways.
	DataServerAddr *net.UDPAddr
	// DataClientIP is the IP from which encapsulated data traffic is sent to other gateways.
	DataClientIP net.IP

	// DataIP is the IP that should be used for dataplane traffic.
	DataAddr *net.UDPAddr

	// Daemon is the API of the SCION Daemon.
	Daemon daemon.Connector

	// RouteSourceIPv4 is the source hint for IPv4 routes added to the Linux routing table.
	RouteSourceIPv4 net.IP
	// RouteSourceIPv6 is the source hint for IPv6 routes added to the Linux routing table.
	RouteSourceIPv6 net.IP
	// TunnelName is the device name for the Linux global tunnel device.
	TunnelName string

	// RoutingTableReader is used for routing the packets.
	RoutingTableReader control.RoutingTableReader
	// RoutingTableSwapper is used for switching the routing tables.
	RoutingTableSwapper control.RoutingTableSwapper

	// ConfigReloadTrigger can be used to trigger a config reload.
	ConfigReloadTrigger chan struct{}
	// HTTPEndpoints is a map of http endpoints.
	HTTPEndpoints service.StatusPages
	// HTTPServeMux is the http server mux that is used to expose gateway http
	// endpoints.
	HTTPServeMux *http.ServeMux

	// Metrics are the metrics exported by the gateway.
	Metrics *Metrics
}

func (g *Gateway) Run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	logger.Debug("Gateway starting up...")

	// *************************************************************************
	// Set up support for Linux tunnel devices.
	// *************************************************************************
	var fwMetrics dataplane.IPForwarderMetrics
	if g.Metrics != nil {
		fwMetrics.IPPktBytesLocalRecv = metrics.NewPromCounter(
			g.Metrics.IPPktBytesLocalReceivedTotal)
		fwMetrics.IPPktsLocalRecv = metrics.NewPromCounter(g.Metrics.IPPktsLocalReceivedTotal)
		fwMetrics.IPPktsInvalid = metrics.CounterWith(
			metrics.NewPromCounter(g.Metrics.IPPktsDiscardedTotal), "reason", "invalid")
		fwMetrics.IPPktsFragmented = metrics.CounterWith(
			metrics.NewPromCounter(g.Metrics.IPPktsDiscardedTotal), "reason", "fragmented")
		fwMetrics.ReceiveLocalErrors = metrics.NewPromCounter(g.Metrics.ReceiveLocalErrorsTotal)
		fwMetrics.IPPktsNoRoute = metrics.CounterWith(
			metrics.NewPromCounter(g.Metrics.IPPktsDiscardedTotal), "reason", "no_route")
	}

	tunnelName := g.TunnelName
	if tunnelName == "" {
		tunnelName = "tun0"
	}

	tunnelReader := TunnelReader{
		DeviceOpener: xnet.UseNameResolver(
			routemgr.FixedTunnelName(tunnelName),
			xnet.OpenerWithOptions(ctx),
		),
		Router:  g.RoutingTableReader,
		Metrics: fwMetrics,
	}
	deviceManager := &routemgr.SingleDeviceManager{
		DeviceOpener: tunnelReader.GetDeviceOpenerWithAsyncReader(ctx),
	}

	logger.Debug("Egress started")

	routePublisherFactory := createRouteManager(ctx, deviceManager)

	// *********************************************
	// Initialize base SCION network information: IA
	// *********************************************
	topoReloader, err := daemon.NewReloadingTopology(ctx, g.Daemon)
	if err != nil {
		return serrors.Wrap("loading topology", err)
	}
	topo := topoReloader.Topology()
	go func() {
		defer log.HandlePanic()
		topoReloader.Run(ctx, 10*time.Second)
	}()
	localIA := topo.LocalIA
	logger.Info("Learned local IA from SCION Daemon", "ia", localIA)

	// *************************************************************************
	// Set up path monitoring. The path monitor runs an the SCION/UDP stack
	// using the control address and uses traceroute packets to check if paths
	// are healthy. Paths are fetched from a Daemon. Data-plane revocations are
	// forwarded to the Daemon to improve path construction.
	// *************************************************************************

	pathRouter := &snet.BaseRouter{Querier: daemon.Querier{Connector: g.Daemon, IA: localIA}}
	revocationHandler := daemon.RevHandler{Connector: g.Daemon}

	var pathsMonitored, sessionPathsAvailable metrics.Gauge
	var probesSent, probesReceived, probesSendErrors func(addr.IA) metrics.Counter
	if g.Metrics != nil {
		perRemoteCounter := func(c *prometheus.CounterVec) func(addr.IA) metrics.Counter {
			return func(remote addr.IA) metrics.Counter {
				return metrics.CounterWith(
					metrics.NewPromCounter(c),
					"remote_isd_as", remote.String(),
				)
			}
		}
		pathsMonitored = metrics.NewPromGauge(g.Metrics.PathsMonitored)
		sessionPathsAvailable = metrics.NewPromGauge(g.Metrics.SessionPathsAvailable)

		probesSent = perRemoteCounter(g.Metrics.PathProbesSent)
		probesReceived = perRemoteCounter(g.Metrics.PathProbesReceived)
		probesSendErrors = perRemoteCounter(g.Metrics.PathProbesSendErrors)
	}
	revStore := &pathhealth.MemoryRevocationStore{}

	// periodically clean up the revocation store.
	revCleaner := periodic.Start(periodic.Func{
		Task: func(ctx context.Context) {
			revStore.Cleanup(ctx)
		},
		TaskName: "revocation_store_cleaner",
	}, 30*time.Second, 30*time.Second)
	defer revCleaner.Stop()

	pathMonitor := &PathMonitor{
		Monitor: &pathhealth.Monitor{
			RemoteWatcherFactory: &pathhealth.DefaultRemoteWatcherFactory{
				Router: pathRouter,
				PathWatcherFactory: &pathhealth.DefaultPathWatcherFactory{
					LocalIA:                localIA,
					LocalIP:                g.PathMonitorIP,
					RevocationHandler:      revocationHandler,
					ProbeInterval:          0, // using default for now
					ProbesSent:             probesSent,
					ProbesReceived:         probesReceived,
					ProbesSendErrors:       probesSendErrors,
					SCMPErrors:             g.Metrics.SCMPErrors,
					SCIONPacketConnMetrics: g.Metrics.SCIONPacketConnMetrics,
					Topology:               topo,
				},
				PathUpdateInterval: PathUpdateInterval(ctx),
				PathFetchTimeout:   0, // using default for now
				PathsMonitored: func(remote addr.IA) metrics.Gauge {
					return metrics.GaugeWith(pathsMonitored, "remote_isd_as", remote.String())
				},
			},
		},
		revStore:              revStore,
		sessionPathsAvailable: sessionPathsAvailable,
	}

	// *************************************************************************
	// Set up the configuration pipelines for session construction.
	//
	// Two policies are propagated through the pipeline:
	//   - traffic policy, originated from the traffic policy file
	//   - routing policy, originated from the routing policy file
	//
	// The traffic policy also dictates which remote ASes are going to be polled
	// for prefix discovery by the Remote Monitor.
	//
	// Prefixes are filtered (according to the last seen routing policy) and
	// then aggregated, before being pushed to session construction.
	// *************************************************************************

	legacySessionPolicyAdapter := &control.LegacySessionPolicyAdapter{}

	// We know we have two subscribers, so we initialize the subscriptions right from the start.
	// Once subscribed, publish immediately.
	configPublisher := &control.ConfigPublisher{}
	remoteIAsChannel := configPublisher.SubscribeRemoteIAs()
	sessionPoliciesChannel := configPublisher.SubscribeSessionPolicies()

	configLoader := Loader{
		SessionPoliciesFile: g.TrafficPolicyFile,
		RoutingPolicyFile:   g.RoutingPolicyFile,
		Publisher:           configPublisher,
		Trigger:             g.ConfigReloadTrigger,
		SessionPolicyParser: legacySessionPolicyAdapter,
	}

	go func() {
		defer log.HandlePanic()
		if err := configLoader.Run(ctx); err != nil {
			panic(err)
		}
	}()

	// Trigger the initial load of the config. This is done in a go routine
	// since it still might block until everything is set up.
	go func() {
		defer log.HandlePanic()
		g.ConfigReloadTrigger <- struct{}{}
		logger.Debug("Initial traffic policy and routing policy files loaded.")
	}()

	// Initialize the channel between the prefix aggregator and session constructor.
	routingUpdatesChannel := make(chan control.RemoteGateways)

	// Set up the prefix aggregator that will collect prefixes discovered by the Remote Monitor. Use
	// a prefixes filter that uses the monitored traffic policy to ensure that updates to the
	// routing policy are caught.
	//
	// Note that it might take some time for a new routing policy to take effect, because once a
	// prefix is dropped due to routing policy, it is forgotten. If the routing policy changes to
	// allow it, it must be seen again through discovery before it passes through the aggregator.
	prefixAggregator := &control.Aggregator{
		RoutingUpdateChan: routingUpdatesChannel,
		ReportingInterval: 1 * time.Second,
		ExpiryInterval:    30 * time.Second,
	}
	pfMetrics := control.PrefixesFilterMetrics{}
	if g.Metrics != nil {
		pfMetrics.PrefixesAccepted = metrics.NewPromGauge(g.Metrics.PrefixesAccepted)
		pfMetrics.PrefixesRejected = metrics.NewPromGauge(g.Metrics.PrefixesRejected)
	}
	filteredPrefixAggregator := &control.PrefixesFilter{
		LocalIA:        localIA,
		PolicyProvider: configPublisher,
		Consumer:       prefixAggregator,
		Metrics:        pfMetrics,
	}

	go func() {
		defer log.HandlePanic()
		if err := prefixAggregator.Run(ctx); err != nil {
			panic(err)
		}
	}()

	// ***********************************************************************************
	// Set up QUIC client dialer and QUIC server listener
	//
	// The client dialer is needed by the Remote Monitor, for discovering remote
	// gateways and network prefixes.
	//
	// The server listener is needed to handle prefix fetching requests.
	// ***********************************************************************************

	// Generate throwaway self-signed TLS certificates. These DO NOT PROVIDE ANY SECURITY.
	ephemeralTLSConfig, err := infraenv.GenerateTLSConfig()
	if err != nil {
		return serrors.Wrap("unable to generate TLS config", err)
	}

	// scionNetworkNoSCMP is the network for the QUIC server connection. Because SCMP errors
	// will cause the server's accepts to fail, we ignore SCMP.
	scionNetworkNoSCMP := &snet.SCIONNetwork{
		Topology: topo,
		// Discard all SCMP propagation, to avoid accept/read errors on the
		// QUIC server/client.
		SCMPHandler: snet.SCMPPropagationStopper{
			Handler: snet.DefaultSCMPHandler{
				RevocationHandler: revocationHandler,
				SCMPErrors:        g.Metrics.SCMPErrors,
			},
			Log: log.FromCtx(ctx).Debug,
		},
		PacketConnMetrics: g.Metrics.SCIONPacketConnMetrics,
		Metrics:           g.Metrics.SCIONNetworkMetrics,
	}

	// Initialize the UDP/SCION QUIC conn for outgoing Gateway Discovery RPCs and outgoing Prefix
	// Fetching. Open up a random high port for this.
	clientConn, err := scionNetworkNoSCMP.Listen(
		context.TODO(),
		"udp",
		&net.UDPAddr{IP: g.ControlClientIP},
	)
	if err != nil {
		return serrors.Wrap("unable to initialize client QUIC connection", err)
	}
	logger.Info("QUIC client connection initialized",
		"local_addr", clientConn.LocalAddr())

	quicClientDialer := &squic.ConnDialer{
		Transport: &quic.Transport{
			Conn: clientConn,
		},
		TLSConfig: ephemeralTLSConfig,
	}

	// remoteMonitor subscribes to the list of known remote ASes, and launches workers that
	// monitor which gateways exist in each AS, and what prefixes each gateway advertises.
	// Prefixes learned by the remote monitor are pushed to prefix aggregation.
	var rmMetric func(addr.IA) metrics.Gauge
	var rmChangesMetric func(addr.IA) metrics.Counter
	var rmErrorsMetric func(addr.IA) metrics.Counter
	var rmPrefixErrorsMetric func(addr.IA) metrics.Counter
	if g.Metrics != nil {
		rmMetric = func(ia addr.IA) metrics.Gauge {
			return metrics.GaugeWith(metrics.NewPromGauge(g.Metrics.Remotes),
				"remote_isd_as", ia.String())
		}
		rmChangesMetric = func(ia addr.IA) metrics.Counter {
			return metrics.CounterWith(metrics.NewPromCounter(g.Metrics.RemotesChanges),
				"remote_isd_as", ia.String())
		}
		rmErrorsMetric = func(ia addr.IA) metrics.Counter {
			return metrics.CounterWith(metrics.NewPromCounter(g.Metrics.RemoteDiscoveryErrors),
				"remote_isd_as", ia.String())
		}
		rmPrefixErrorsMetric = func(ia addr.IA) metrics.Counter {
			return metrics.CounterWith(metrics.NewPromCounter(g.Metrics.PrefixFetchErrors),
				"remote_isd_as", ia.String())
		}
	}

	// scionNetwork is the network for all SCION connections, with the exception of the QUIC server
	// and client connection.
	scionNetwork := &snet.SCIONNetwork{
		Topology: topo,
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: revocationHandler,
			SCMPErrors:        g.Metrics.SCMPErrors,
		},
		PacketConnMetrics: g.Metrics.SCIONPacketConnMetrics,
		Metrics:           g.Metrics.SCIONNetworkMetrics,
	}
	remoteMonitor := &control.RemoteMonitor{
		IAs:                   remoteIAsChannel,
		RemotesMonitored:      rmMetric,
		RemotesChanges:        rmChangesMetric,
		RemoteDiscoveryErrors: rmErrorsMetric,
		PrefixFetchErrors:     rmPrefixErrorsMetric,
		GatewayWatcherFactory: &WatcherFactory{
			Aggregator:  filteredPrefixAggregator,
			PathMonitor: pathMonitor,
			Policies: &policies.Policies{
				PathPolicy: control.DefaultPathPolicy,
			},
			Dialer: &libgrpc.QUICDialer{
				Dialer: quicClientDialer,
				Rewriter: &infraenv.AddressRewriter{
					// Use the local Daemon to construct paths to the target AS.
					Router: pathRouter,
					// We never resolve addresses in the local AS, so pass a nil here.
					SVCRouter: nil,
					Resolver: &svc.Resolver{
						LocalIA: localIA,
						// Reuse the network with SCMP error support.
						Network: scionNetwork,
						LocalIP: g.ServiceDiscoveryClientIP,
					},
				},
			},
		},
	}

	go func() {
		defer log.HandlePanic()
		if err := remoteMonitor.Run(ctx); err != nil {
			panic(err)
		}
	}()
	logger.Debug("Remote monitor started.")

	serverConn, err := scionNetworkNoSCMP.Listen(
		context.TODO(),
		"udp",
		g.ControlServerAddr,
	)
	if err != nil {
		return serrors.Wrap("unable to initialize server QUIC connection", err)
	}
	logger.Info("QUIC server connection initialized",
		"local_addr", serverConn.LocalAddr())

	internalQUICServerListener, err := quic.Listen(serverConn, ephemeralTLSConfig, nil)
	if err != nil {
		return serrors.Wrap("unable to initializer server QUIC listener", err)
	}
	// Wrap in net.Listener for use with gRPC
	quicServerListener := squic.NewConnListener(internalQUICServerListener)

	var paMetric metrics.Gauge
	if g.Metrics != nil {
		paMetric = metrics.NewPromGauge(g.Metrics.PrefixesAdvertised)
	}
	discoveryServer := grpc.NewServer(
		libgrpc.UnaryServerInterceptor(),
		libgrpc.DefaultMaxConcurrentStreams(),
	)
	gatewaypb.RegisterIPPrefixesServiceServer(
		discoveryServer,
		controlgrpc.IPPrefixServer{
			LocalIA: localIA,
			Advertiser: &SelectAdvertisedRoutes{
				ConfigPublisher: configPublisher,
			},
			PrefixesAdvertised: paMetric,
		},
	)

	go func() {
		defer log.HandlePanic()
		if err := discoveryServer.Serve(quicServerListener); err != nil {
			panic(err)
		}
	}()

	logger.Debug("QUIC stack initialized.")

	// *********************************************************************************
	// Enable probe handler on the probe port. The probe handler will listen for probes
	// received from the session monitors of the remote gateway.
	// *********************************************************************************

	probeConn, err := scionNetwork.Listen(context.TODO(), "udp", g.ProbeServerAddr)
	if err != nil {
		return serrors.Wrap("creating server probe conn", err)
	}
	probeServer := controlgrpc.ProbeDispatcher{}
	probeServerCtx, probeServerCancel := context.WithCancel(context.Background())
	defer probeServerCancel()
	go func() {
		defer log.HandlePanic()
		if err := probeServer.Listen(probeServerCtx, probeConn); err != nil {
			panic(err)
		}
	}()

	// Start dataplane ingress
	if err := StartIngress(ctx, scionNetwork, g.DataServerAddr, deviceManager,
		g.Metrics); err != nil {

		return err
	}
	logger.Debug("Ingress started")

	// *************************************************
	// Connect Session Configurator to Engine Controller
	// *************************************************

	sessionConfigurations := make(chan []*control.SessionConfig)

	sessionConfigurator := &control.SessionConfigurator{
		SessionPolicies:       sessionPoliciesChannel,
		RoutingUpdates:        routingUpdatesChannel,
		SessionConfigurations: sessionConfigurations,
	}
	go func() {
		defer log.HandlePanic()
		if err := sessionConfigurator.Run(ctx); err != nil {
			panic(err)
		}
	}()
	logger.Debug("Session configurator started")
	g.HTTPEndpoints["sessionconfigurator"] = service.StatusPage{
		Info: "session configurator diagnostics",
		Handler: func(w http.ResponseWriter, _ *http.Request) {
			sessionConfigurator.DiagnosticsWrite(w)
		},
	}

	// Start control-plane configuration watcher and forwarding engine controller
	engineController := &control.EngineController{
		ConfigurationUpdates: sessionConfigurations,
		RoutingTableSwapper:  g.RoutingTableSwapper,
		RoutingTableFactory: RoutingTableFactory{
			RoutePublisherFactory: routePublisherFactory,
		},
		EngineFactory: &control.DefaultEngineFactory{
			PathMonitor: pathMonitor,
			ProbeConnFactory: PacketConnFactory{
				Network: scionNetwork,
				Addr:    &net.UDPAddr{IP: g.ProbeClientIP},
			},
			DeviceManager: deviceManager,
			DataplaneSessionFactory: DataplaneSessionFactory{
				PacketConnFactory: PacketConnFactory{
					Network: scionNetwork,
					Addr:    &net.UDPAddr{IP: g.DataClientIP},
				},
				Metrics: CreateSessionMetrics(g.Metrics),
			},
			Metrics: CreateEngineMetrics(g.Metrics),
		},
		RoutePublisherFactory: routePublisherFactory,
		RouteSourceIPv4:       g.RouteSourceIPv4,
		RouteSourceIPv6:       g.RouteSourceIPv6,
		SwapDelay:             swapDelay,
	}
	go func() {
		defer log.HandlePanic()
		if err := engineController.Run(ctx); err != nil {
			panic(err)
		}
	}()
	logger.Debug("Engine controller started")

	g.HTTPEndpoints["engine"] = service.StatusPage{
		Info: "gateway diagnostics",
		Handler: func(w http.ResponseWriter, _ *http.Request) {
			engineController.DiagnosticsWrite(w)
		},
	}
	g.HTTPEndpoints["status"] = service.StatusPage{
		Info: "gateway status (remote ASes, sessions, paths)",
		Handler: func(w http.ResponseWriter, _ *http.Request) {
			engineController.Status(w)
		},
	}
	g.HTTPEndpoints["diagnostics/prefixwatcher"] = service.StatusPage{
		Info: "IP prefixes incoming via SGRP",
		Handler: func(w http.ResponseWriter, _ *http.Request) {
			remoteMonitor.DiagnosticsWrite(w)
		},
	}
	g.HTTPEndpoints["diagnostics/sgrp"] = service.StatusPage{
		Info:    "SGRP diagnostics",
		Handler: g.diagnosticsSGRP(routePublisherFactory, configPublisher),
	}

	// XXX(scrye): Use an empty file here because the server often doesn't have
	// write access to its configuration folder.
	g.HTTPEndpoints["ip-routing/policy"] = service.StatusPage{
		Info: "IP routing policy (supports PUT)",
		Handler: routing.NewPolicyHandler(
			RoutingPolicyPublisherAdapter{ConfigPublisher: configPublisher}, ""),
	}

	if err := g.HTTPEndpoints.Register(g.HTTPServeMux, g.ID); err != nil {
		return serrors.Wrap("registering HTTP pages", err)
	}
	<-ctx.Done()
	return nil
}

func (g *Gateway) diagnosticsSGRP(
	routePublisherFactory control.PublisherFactory,
	pub *control.ConfigPublisher,
) http.HandlerFunc {

	return func(w http.ResponseWriter, _ *http.Request) {
		var d struct {
			Advertise struct {
				Static []string `json:"static"`
			} `json:"advertise"`
			Learned struct {
				Dynamic []string `json:"dynamic"`
			} `json:"learned"`
		}
		// Avoid null in json output.
		d.Advertise.Static = []string{}
		d.Learned.Dynamic = []string{}

		for _, s := range routing.StaticAdvertised(pub.RoutingPolicy()) {
			d.Advertise.Static = append(d.Advertise.Static, s.String())
		}
		if p, ok := routePublisherFactory.(interface{ Diagnostics() control.Diagnostics }); ok {
			for _, r := range p.Diagnostics().Routes {
				d.Learned.Dynamic = append(d.Learned.Dynamic, r.Prefix.String())
			}
		}
		jsonData, err := json.MarshalIndent(d, "", "    ")
		if err != nil {
			log.Error("json marshalling", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(jsonData)
	}
}

func PathUpdateInterval(ctx context.Context) time.Duration {
	logger := log.FromCtx(ctx)
	s, ok := os.LookupEnv("SCION_EXPERIMENTAL_GATEWAY_PATH_UPDATE_INTERVAL")
	if !ok {
		return 0
	}
	dur, err := util.ParseDuration(s)
	if err != nil {
		logger.Info(
			"Failed to parse SCION_EXPERIMENTAL_GATEWAY_PATH_UPDATE_INTERVAL, using default",
			"err", err)
		return 0
	}
	return dur
}

func CreateIngressMetrics(m *Metrics) dataplane.IngressMetrics {
	if m == nil {
		return dataplane.IngressMetrics{}
	}
	return dataplane.IngressMetrics{
		IPPktBytesRecv:       metrics.NewPromCounter(m.IPPktBytesReceivedTotal),
		IPPktsRecv:           metrics.NewPromCounter(m.IPPktsReceivedTotal),
		IPPktBytesLocalSent:  metrics.NewPromCounter(m.IPPktBytesLocalSentTotal),
		IPPktsLocalSent:      metrics.NewPromCounter(m.IPPktsLocalSentTotal),
		FrameBytesRecv:       metrics.NewPromCounter(m.FrameBytesReceivedTotal),
		FramesRecv:           metrics.NewPromCounter(m.FramesReceivedTotal),
		FramesDiscarded:      metrics.NewPromCounter(m.FramesDiscardedTotal),
		SendLocalError:       metrics.NewPromCounter(m.SendLocalErrorsTotal),
		ReceiveExternalError: metrics.NewPromCounter(m.ReceiveExternalErrorsTotal),
	}
}

func StartIngress(ctx context.Context, scionNetwork *snet.SCIONNetwork, dataAddr *net.UDPAddr,
	deviceManager control.DeviceManager, metrics *Metrics) error {

	logger := log.FromCtx(ctx)
	dataplaneServerConn, err := scionNetwork.Listen(
		context.TODO(),
		"udp",
		dataAddr,
	)
	if err != nil {
		return serrors.Wrap("creating ingress conn", err)
	}
	ingressMetrics := CreateIngressMetrics(metrics)
	ingressServer := &dataplane.IngressServer{
		Conn:          dataplaneServerConn,
		DeviceManager: deviceManager,
		Metrics:       ingressMetrics,
	}
	go func() {
		defer log.HandlePanic()
		if err := ingressServer.Run(ctx); err != nil {
			logger.Error("Ingress server error", "err", err)
			panic(err)
		}
	}()
	return nil
}

func CreateSessionMetrics(m *Metrics) dataplane.SessionMetrics {
	if m == nil {
		return dataplane.SessionMetrics{}
	}
	return dataplane.SessionMetrics{
		IPPktBytesSent:     metrics.NewPromCounter(m.IPPktBytesSentTotal),
		IPPktsSent:         metrics.NewPromCounter(m.IPPktsSentTotal),
		FrameBytesSent:     metrics.NewPromCounter(m.FrameBytesSentTotal),
		FramesSent:         metrics.NewPromCounter(m.FramesSentTotal),
		SendExternalErrors: metrics.NewPromCounter(m.SendExternalErrorsTotal),
	}
}

func CreateEngineMetrics(m *Metrics) control.EngineMetrics {
	if m == nil {
		return control.EngineMetrics{
			RouterMetrics: createRouterMetrics(m),
		}
	}
	return control.EngineMetrics{
		SessionMetrics: control.SessionMetrics{
			PathChanges: metrics.NewPromCounter(m.SessionPathChanges),
		},
		SessionMonitorMetrics: control.SessionMonitorMetrics{
			Probes:       metrics.NewPromCounter(m.SessionProbes),
			ProbeReplies: metrics.NewPromCounter(m.SessionProbeReplies),
			IsHealthy:    metrics.NewPromGauge(m.SessionIsHealthy),
			StateChanges: metrics.NewPromCounter(m.SessionStateChanges),
		},
		RouterMetrics: createRouterMetrics(m),
	}
}

func createRouterMetrics(m *Metrics) control.RouterMetrics {
	if m == nil {
		return control.RouterMetrics{
			RoutingChainHealthy: func(routingChain int) metrics.Gauge { return nil },
			SessionsAlive:       func(routingChain int) metrics.Gauge { return nil },
			SessionChanges:      func(routingChain int) metrics.Counter { return nil },
			StateChanges:        func(routingChain int) metrics.Counter { return nil },
		}
	}
	return control.RouterMetrics{
		RoutingChainHealthy: func(routingChain int) metrics.Gauge {
			return metrics.NewPromGauge(m.RoutingChainHealthy).
				With("routing_chain_id", strconv.Itoa(routingChain))
		},
		SessionsAlive: func(routingChain int) metrics.Gauge {
			return metrics.NewPromGauge(m.RoutingChainAliveSessions).
				With("routing_chain_id", strconv.Itoa(routingChain))
		},
		SessionChanges: func(routingChain int) metrics.Counter {
			return metrics.NewPromCounter(m.RoutingChainSessionChanges).
				With("routing_chain_id", strconv.Itoa(routingChain))
		},
		StateChanges: func(routingChain int) metrics.Counter {
			return metrics.NewPromCounter(m.RoutingChainStateChanges).
				With("routing_chain_id", strconv.Itoa(routingChain))
		},
	}
}

func createRouteManager(ctx context.Context,
	deviceManager control.DeviceManager) control.PublisherFactory {

	linux := &routemgr.Linux{DeviceManager: deviceManager}
	go func() {
		defer log.HandlePanic()
		linux.Run(ctx)
	}()
	return linux
}

type TunnelReader struct {
	DeviceOpener control.DeviceOpener
	Router       control.RoutingTableReader
	Metrics      dataplane.IPForwarderMetrics
}

func (r *TunnelReader) GetDeviceOpenerWithAsyncReader(ctx context.Context) control.DeviceOpener {
	f := func(ctx context.Context, ia addr.IA) (control.Device, error) {
		logger := log.FromCtx(ctx)
		handle, err := r.DeviceOpener.Open(ctx, ia)
		if err != nil {
			return nil, serrors.Wrap("opening device", err)
		}

		forwarder := &dataplane.IPForwarder{
			Reader:       handle,
			RoutingTable: r.Router,
			Metrics:      r.Metrics,
		}

		go func() {
			defer log.HandlePanic()
			if err := forwarder.Run(ctx); err != nil {
				logger.Debug("Encountered error when reading from tun", "err", err)
				return
			}
		}()

		return handle, nil
	}
	return control.DeviceOpenerFunc(f)
}
