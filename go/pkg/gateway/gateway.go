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
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/pkg/gateway/config"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	controlgrpc "github.com/scionproto/scion/go/pkg/gateway/control/grpc"
	"github.com/scionproto/scion/go/pkg/gateway/dataplane"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth/policies"
	"github.com/scionproto/scion/go/pkg/gateway/routing"
	"github.com/scionproto/scion/go/pkg/gateway/routing/exporters/linux"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	gatewaypb "github.com/scionproto/scion/go/pkg/proto/gateway"
	"github.com/scionproto/scion/go/pkg/service"
)

type WatcherFactory struct {
	Dialer      libgrpc.Dialer
	PathMonitor control.PathMonitor
	Aggregator  control.PrefixConsumer
	Policies    *policies.Policies
}

func (wf *WatcherFactory) New(remote addr.IA,
	metrics control.GatewayWatcherMetrics) control.Runner {

	pather := wf.PathMonitor.Register(remote, wf.Policies, 0)

	return &control.GatewayWatcher{
		Remote: remote,
		Discoverer: controlgrpc.Discoverer{
			Remote: remote,
			Dialer: wf.Dialer,
			Paths:  pather,
		},
		Template: control.PrefixWatcherConfig{
			Consumer: wf.Aggregator,
			Fetcher: &controlgrpc.PrefixFetcher{
				Remote: remote,
				Dialer: wf.Dialer,
				Pather: pather,
			},
		},
		Metrics: metrics,
	}
}

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
	return &dataplane.Session{
		SessionID:          id,
		GatewayAddr:        *remoteAddr.(*net.UDPAddr),
		DataPlaneConn:      conn,
		PathStatsPublisher: dpf.PathStatsPublisher,
		Metrics:            metrics,
	}
}

type PacketConnFactory struct {
	Network *snet.SCIONNetwork
	Addr    *net.UDPAddr
}

func (pcf PacketConnFactory) New() (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := pcf.Network.Listen(ctx, "udp", pcf.Addr, addr.SvcNone)
	if err != nil {
		return nil, serrors.WrapStr("creating packet conn", err)
	}
	return conn, nil
}

type RoutingTableFactory struct {
	Device netlink.Link
	Source net.IP
}

func (rtf RoutingTableFactory) New(
	routingChains []*control.RoutingChain) (control.RoutingTable, error) {

	if ExperimentalExportMainRT() {
		return dataplane.NewRoutingTable(linux.RouteExporter{
			Device: rtf.Device,
			Source: rtf.Source,
		}, routingChains), nil
	}
	return dataplane.NewRoutingTable(nil, routingChains), nil
}

// ignoreSCMP ignores all received SCMP packets.
//
// XXX(scrye): This is needed such that the QUIC server does not shut down when
// receiving a SCMP error. DO NOT REMOVE!
type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	return nil
}

// ConfigPublisherAdvertiser computes the networks that should be advertised depending
// on the state of the last published routing policy file.
type ConfigPublisherAdvertiser struct {
	ConfigPublisher *control.ConfigPublisher
}

func (a *ConfigPublisherAdvertiser) AdvertiseList(from, to addr.IA) []*net.IPNet {
	policy := a.ConfigPublisher.RoutingPolicy()
	return routing.AdvertiseList(*policy, from, to)

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
	PathMonitorIP net.IP
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

	// Dispatcher is the API of the SCION Dispatcher on the local host.
	Dispatcher reliable.Dispatcher

	// Daemon is the API of the SCION Daemon.
	Daemon sciond.Connector

	// InternalDevice is the tunnel interface from which packets are read.
	InternalDevice io.ReadWriteCloser
	// RouteDevice is the device for routes added to the Linux routing table.
	RouteDevice netlink.Link
	// RouteSource is the source for routes added to the Linux routing table.
	RouteSource net.IP

	// ConfigReloadTrigger can be used to trigger a config reload.
	ConfigReloadTrigger chan struct{}
	// HTTPEndpoints is a map of http endpoints.
	HTTPEndpoints service.StatusPages
	// HTTPServeMux is the http server mux that is used to expose gateway http
	// endpoints.
	HTTPServeMux *http.ServeMux

	// Logger is the base logger for all modules initialized by the gateway.
	Logger log.Logger
	// Metrics are the metrics exported by the gateway.
	Metrics *Metrics
}

func (g *Gateway) Run() error {
	log.SafeDebug(g.Logger, "Gateway starting up...")

	localIA, err := g.Daemon.LocalIA(context.Background())
	if err != nil {
		return serrors.WrapStr("unable to learn local ISD-AS number", err)
	}
	log.SafeInfo(g.Logger, "Learned local IA from SCION Daemon", "ia", localIA)

	reconnectingDispatcher := reconnect.NewDispatcherService(g.Dispatcher)

	// *************************************************************************
	// Set up path monitoring. The path monitor runs an the SCION/UDP stack
	// using the control address and uses traceroute packets to check if paths
	// are healthy. Paths are fetched from a Daemon. Data-plane revocations are
	// forwarded to the Daemon to improve path construction.
	// *************************************************************************
	pathMonitorConnection, pathMonitorPort, err := reconnectingDispatcher.Register(
		context.Background(),
		localIA,
		&net.UDPAddr{IP: g.PathMonitorIP},
		addr.SvcNone,
	)
	if err != nil {
		return serrors.WrapStr("unable to open control socket", err)
	}
	log.SafeDebug(g.Logger, "Path monitor connection opened on Raw UDP/SCION",
		"local_ip", g.PathMonitorIP, "local_port", pathMonitorPort)

	pathRouter := &snet.BaseRouter{Querier: sciond.Querier{Connector: g.Daemon, IA: localIA}}
	revocationHandler := sciond.RevHandler{Connector: g.Daemon}

	var pathsMonitored, sessionPathsAvailable metrics.Gauge
	if g.Metrics != nil {
		pathsMonitored = metrics.NewPromGauge(g.Metrics.PathsMonitored)
		sessionPathsAvailable = metrics.NewPromGauge(g.Metrics.SessionPathsAvailable)
	}
	revStore := &pathhealth.MemoryRevocationStore{
		Logger: g.Logger,
	}
	pathMonitor := &PathMonitor{
		Monitor: &pathhealth.Monitor{
			LocalIA:           localIA,
			LocalIP:           g.PathMonitorIP,
			Conn:              pathMonitorConnection,
			RevocationHandler: revocationHandler,
			Router:            pathRouter,
			RemoteWatcherFactory: &pathhealth.DefaultRemoteWatcherFactory{
				PathWatcherFactory: &pathhealth.DefaultPathWatcherFactory{
					Logger: g.Logger,
				},
				Logger:         g.Logger,
				PathsMonitored: pathsMonitored,
			},
			Logger:          g.Logger,
			RevocationStore: revStore,
		},
		revStore:              revStore,
		sessionPathsAvailable: sessionPathsAvailable,
	}
	go func() {
		defer log.HandlePanic()
		pathMonitor.Run()
	}()
	log.SafeInfo(g.Logger, "Path monitor started.")

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

	configLoader := config.Loader{
		SessionPoliciesFile: g.TrafficPolicyFile,
		RoutingPolicyFile:   g.RoutingPolicyFile,
		Publisher:           configPublisher,
		Trigger:             g.ConfigReloadTrigger,
		SessionPolicyParser: legacySessionPolicyAdapter,
		Logger:              g.Logger,
	}

	go func() {
		defer log.HandlePanic()
		if err := configLoader.Run(); err != nil {
			panic(err)
		}
	}()

	// Trigger the initial load of the config. This is done in a go routine
	// since it still might block until everything is set up.
	go func() {
		defer log.HandlePanic()
		g.ConfigReloadTrigger <- struct{}{}
		log.SafeDebug(g.Logger, "Initial traffic policy and routing policy files loaded.")
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
		if err := prefixAggregator.Run(); err != nil {
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
		return serrors.WrapStr("unable to generate TLS config", err)
	}

	// scionNetwork is the network for all SCION connections, with the exception of the QUIC server
	// connection.
	scionNetwork := &snet.SCIONNetwork{
		LocalIA: localIA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			// Enable transparent reconnections to the dispatcher
			Dispatcher: reconnectingDispatcher,
			// Forward revocations to Daemon
			SCMPHandler: snet.DefaultSCMPHandler{
				RevocationHandler: revocationHandler,
			},
		},
	}

	// Initialize the UDP/SCION QUIC conn for outgoing Gateway Discovery RPCs and outgoing Prefix
	// Fetching. Open up a random high port for this.
	clientConn, err := scionNetwork.Listen(
		context.TODO(),
		"udp",
		&net.UDPAddr{IP: g.ControlClientIP},
		addr.SvcNone,
	)
	if err != nil {
		return serrors.WrapStr("unable to initialize client QUIC connection", err)
	}
	log.SafeInfo(g.Logger, "QUIC client connection initialized",
		"local_addr", clientConn.LocalAddr())

	quicClientDialer := &squic.ConnDialer{
		Conn:      clientConn,
		TLSConfig: ephemeralTLSConfig,
	}

	// remoteMonitor subscribes to the list of known remote ASes, and launches workers that
	// monitor which gateways exist in each AS, and what prefixes each gateway advertises.
	// Prefixes learned by the remote monitor are pushed to prefix aggregation.
	var rmMetric metrics.Gauge
	if g.Metrics != nil {
		rmMetric = metrics.NewPromGauge(g.Metrics.Remotes)
	}
	remoteMonitor := &control.RemoteMonitor{
		IAs:              remoteIAsChannel,
		Logger:           g.Logger,
		RemotesMonitored: rmMetric,
		GatewayWatcherFactory: &WatcherFactory{
			Aggregator:  filteredPrefixAggregator,
			PathMonitor: pathMonitor,
			Policies: &policies.Policies{
				PathPolicy: control.DefaultPathPolicy,
			},
			Dialer: &libgrpc.QUICDialer{
				Dialer: quicClientDialer,
				Rewriter: &messenger.AddressRewriter{
					// Use the local Daemon to construct paths to the target AS.
					Router: pathRouter,
					// We never resolve addresses in the local AS, so pass a nil here.
					SVCRouter: nil,
					Resolver: &svc.Resolver{
						LocalIA: localIA,
						// Reuse the network with SCMP error support.
						ConnFactory: scionNetwork.Dispatcher,
						LocalIP:     g.ServiceDiscoveryClientIP,
					},
					SVCResolutionFraction: 1.337,
				},
			},
		},
	}

	go func() {
		defer log.HandlePanic()
		if err := remoteMonitor.Run(); err != nil {
			panic(err)
		}
	}()
	log.SafeDebug(g.Logger, "Remote monitor started.")

	// scionNetworkNoSCMP is the network for the QUIC server connection. Because SCMP errors
	// will cause the server's accepts to fail, we ignore SCMP.
	scionNetworkNoSCMP := &snet.SCIONNetwork{
		LocalIA: localIA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			// Enable transparent reconnections to the dispatcher
			Dispatcher: reconnectingDispatcher,
			// Discard all SCMP, to avoid accept errors on the QUIC server.
			SCMPHandler: ignoreSCMP{},
		},
	}
	serverConn, err := scionNetworkNoSCMP.Listen(
		context.TODO(),
		"udp",
		g.ControlServerAddr,
		addr.SvcNone,
	)
	if err != nil {
		return serrors.WrapStr("unable to initialize server QUIC connection", err)
	}
	log.SafeInfo(g.Logger, "QUIC server connection initialized",
		"local_addr", serverConn.LocalAddr())

	internalQUICServerListener, err := quic.Listen(serverConn, ephemeralTLSConfig, nil)
	if err != nil {
		return serrors.WrapStr("unable to initializer server QUIC listener", err)
	}
	// Wrap in net.Listener for use with gRPC
	quicServerListener := squic.NewConnListener(internalQUICServerListener)

	var paMetric metrics.Gauge
	if g.Metrics != nil {
		paMetric = metrics.NewPromGauge(g.Metrics.PrefixesAdvertised)
	}
	discoveryServer := grpc.NewServer(libgrpc.UnaryServerInterceptor())
	gatewaypb.RegisterIPPrefixesServiceServer(
		discoveryServer,
		controlgrpc.IPPrefixServer{
			LocalIA:            localIA,
			Advertiser:         &ConfigPublisherAdvertiser{ConfigPublisher: configPublisher},
			PrefixesAdvertised: paMetric,
		},
	)

	go func() {
		defer log.HandlePanic()
		if err := discoveryServer.Serve(quicServerListener); err != nil {
			panic(err)
		}
	}()

	log.SafeDebug(g.Logger, "QUIC stack initialized.")

	// *********************************************************************************
	// Enable probe handler on the probe port. The probe handler will listen for probes
	// received from the session monitors of the remote gateway.
	// *********************************************************************************

	probeConn, err := scionNetwork.Listen(context.TODO(), "udp", g.ProbeServerAddr, addr.SvcNone)
	if err != nil {
		return serrors.WrapStr("creating server probe conn", err)
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
	dataplaneServerConn, err := scionNetwork.Listen(
		context.TODO(),
		"udp",
		g.DataServerAddr,
		addr.SvcNone,
	)
	if err != nil {
		return serrors.WrapStr("creating ingress conn", err)
	}
	ingressMetrics := CreateIngressMetrics(g.Metrics)
	ingressServer := &dataplane.IngressServer{
		Conn:    dataplaneServerConn,
		TUN:     g.InternalDevice,
		Metrics: ingressMetrics,
	}
	go func() {
		defer log.HandlePanic()
		if err := ingressServer.Run(); err != nil {
			log.Error("Ingress server error", "err", err)
			panic(err)
		}
	}()

	// *************************************************
	// Connect Session Configurator to Engine Controller
	// *************************************************

	sessionConfigurations := make(chan []*control.SessionConfig)

	sessionConfigurator := &control.SessionConfigurator{
		SessionPolicies:       sessionPoliciesChannel,
		RoutingUpdates:        routingUpdatesChannel,
		SessionConfigurations: sessionConfigurations,
		Logger:                g.Logger,
	}
	go func() {
		defer log.HandlePanic()
		if err := sessionConfigurator.Run(); err != nil {
			panic(err)
		}
	}()
	log.SafeDebug(g.Logger, "Session configurator started")
	g.HTTPEndpoints["sessionconfigurator"] = func(w http.ResponseWriter, _ *http.Request) {
		sessionConfigurator.DiagnosticsWrite(w)
	}

	routingTable := &dataplane.AtomicRoutingTable{}

	// Start control-plane configuration watcher and forwarding engine controller
	engineController := &control.EngineController{
		ConfigurationUpdates: sessionConfigurations,
		RoutingTableSwapper:  routingTable,
		RoutingTableFactory: RoutingTableFactory{
			Device: g.RouteDevice,
			Source: g.RouteSource,
		},
		EngineFactory: &control.DefaultEngineFactory{
			PathMonitor: pathMonitor,
			ProbeConnFactory: PacketConnFactory{
				Network: scionNetwork,
				Addr:    &net.UDPAddr{IP: g.ProbeClientIP},
			},
			DataplaneSessionFactory: DataplaneSessionFactory{
				PacketConnFactory: PacketConnFactory{
					Network: scionNetwork,
					Addr:    &net.UDPAddr{IP: g.DataClientIP},
				},
				Metrics: CreateSessionMetrics(g.Metrics),
			},
			Logger: g.Logger,
		},
		Logger: g.Logger,
	}
	go func() {
		defer log.HandlePanic()
		if err := engineController.Run(); err != nil {
			panic(err)
		}
	}()
	log.SafeDebug(g.Logger, "Engine controller started")

	g.HTTPEndpoints["engine"] = func(w http.ResponseWriter, _ *http.Request) {
		engineController.DiagnosticsWrite(w)
	}
	g.HTTPEndpoints["status"] = func(w http.ResponseWriter, _ *http.Request) {
		engineController.Status(w)
	}
	var fwMetrics dataplane.IPForwarderMetrics
	if g.Metrics != nil {
		fwMetrics.IPPktBytesLocalRecv = metrics.NewPromCounter(
			g.Metrics.IPPktBytesLocalReceivedTotal)
		fwMetrics.IPPktsLocalRecv = metrics.NewPromCounter(g.Metrics.IPPktsLocalReceivedTotal)
		fwMetrics.IPPktsInvalid = metrics.CounterWith(
			metrics.NewPromCounter(g.Metrics.IPPktsDiscardedTotal),
			"reason", "invalid",
		)
		fwMetrics.ReceiveLocalErrors = metrics.NewPromCounter(g.Metrics.ReceiveLocalErrorsTotal)
	}
	forwarder := &dataplane.IPForwarder{
		Reader:       g.InternalDevice,
		RoutingTable: routingTable,
		Logger:       g.Logger,
		Metrics:      fwMetrics,
	}
	go func() {
		defer log.HandlePanic()
		if err := forwarder.Run(); err != nil {
			panic(err)
		}
	}()
	log.SafeDebug(g.Logger, "IP forwarder started")

	// XXX(scrye): Use an empty file here because the server often doesn't have
	// write access to its configuration folder.
	g.HTTPEndpoints["ip-routing/policy"] = routing.NewPolicyHandler(
		RoutingPolicyPublisherAdapter{ConfigPublisher: configPublisher},
		"")

	if err := g.HTTPEndpoints.Register(g.HTTPServeMux, g.ID); err != nil {
		return serrors.WrapStr("registering HTTP pages", err)
	}
	select {}
}

func ExperimentalExportMainRT() bool {
	return os.Getenv("SCION_EXPERIMENTAL_GATEWAY_MAIN_RT") != ""
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
