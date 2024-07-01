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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/snet"
	snetmetrics "github.com/scionproto/scion/pkg/snet/metrics"
)

// These are the metrics that should be exposed by any gateway implementation.
var (
	IPPktBytesSentTotalMeta = MetricMeta{
		Name:   "gateway_ippkt_bytes_sent_total",
		Help:   "Total IP packet bytes sent to remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as", "policy_id"},
	}
	IPPktsSentTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_sent_total",
		Help:   "Total number of IP packets sent to remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as", "policy_id"},
	}
	IPPktBytesReceivedTotalMeta = MetricMeta{
		Name:   "gateway_ippkt_bytes_received_total",
		Help:   "Total IP packet bytes received from remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	IPPktsReceivedTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_received_total",
		Help:   "Total number of IP packets received from remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	IPPktBytesLocalSentTotalMeta = MetricMeta{
		Name:   "gateway_ippkt_bytes_local_sent_total",
		Help:   "Total IP packet bytes sent to the local network.",
		Labels: []string{"isd_as"},
	}
	IPPktsLocalSentTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_local_sent_total",
		Help:   "Total number of IP packets sent to the local network.",
		Labels: []string{"isd_as"},
	}
	IPPktBytesLocalReceivedTotalMeta = MetricMeta{
		Name:   "gateway_ippkt_bytes_local_received_total",
		Help:   "Total IP packet bytes received from the local network.",
		Labels: []string{},
	}
	IPPktsLocalReceivedTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_local_received_total",
		Help:   "Total number of IP packets received from the local network.",
		Labels: []string{},
	}
	FrameBytesSentTotalMeta = MetricMeta{
		Name:   "gateway_frame_bytes_sent_total",
		Help:   "Total frame bytes sent to remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as", "policy_id"},
	}
	FramesSentTotalMeta = MetricMeta{
		Name:   "gateway_frames_sent_total",
		Help:   "Total number of frames sent to remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as", "policy_id"},
	}
	FrameBytesReceivedTotalMeta = MetricMeta{
		Name:   "gateway_frame_bytes_received_total",
		Help:   "Total frame bytes received from remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	FramesReceivedTotalMeta = MetricMeta{
		Name:   "gateway_frames_received_total",
		Help:   "Total number of frames received from remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	FramesDiscardedTotalMeta = MetricMeta{
		Name:   "gateway_frames_discarded_total",
		Help:   "Total number of discarded frames received from remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as", "reason"},
	}
	IPPktsDiscardedTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_discarded_total",
		Help:   "Total number of discarded IP packets received from the local network.",
		Labels: []string{"reason"},
	}
	SendExternalErrorsTotalMeta = MetricMeta{
		Name:   "gateway_send_external_errors_total",
		Help:   "Total number of errors when sending frames to the network (WAN).",
		Labels: []string{"isd_as"},
	}
	SendLocalErrorsTotalMeta = MetricMeta{
		Name:   "gateway_send_local_errors_total",
		Help:   "Total number of errors when sending IP packets to the network (LAN).",
		Labels: []string{"isd_as"},
	}
	ReceiveExternalErrorsTotalMeta = MetricMeta{
		Name:   "gateway_receive_external_errors_total",
		Help:   "Total number of errors when receiving frames from the network (WAN).",
		Labels: []string{"isd_as"},
	}
	ReceiveLocalErrorsTotalMeta = MetricMeta{
		Name:   "gateway_receive_local_errors_total",
		Help:   "Total number of errors when receiving IP packets from the network (LAN).",
		Labels: []string{"isd_as"},
	}
	PathsMonitoredMeta = MetricMeta{
		Name:   "gateway_paths_monitored",
		Help:   "Total number of paths being monitored by the gateway.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	PathProbesSentMeta = MetricMeta{
		Name:   "gateway_path_probes_sent",
		Help:   "Number of path probes being sent.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	PathProbesReceivedMeta = MetricMeta{
		Name:   "gateway_path_probes_received",
		Help:   "Number of replies to the path probes being received.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	PathProbesSendErrorsMeta = MetricMeta{
		Name:   "gateway_path_probes_send_errors",
		Help:   "Number of send error for path probes.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	SessionProbesMeta = MetricMeta{
		Name:   "gateway_session_probes",
		Help:   "Number of probes sent per session.",
		Labels: []string{"isd_as", "remote_isd_as", "session_id", "policy_id"},
	}
	SessionProbeRepliesMeta = MetricMeta{
		Name:   "gateway_session_probe_replies",
		Help:   "Number of probes received per session.",
		Labels: []string{"isd_as", "remote_isd_as", "session_id", "policy_id"},
	}
	SessionIsHealthyMeta = MetricMeta{
		Name:   "gateway_session_is_healthy",
		Help:   "Flag reflecting session healthiness.",
		Labels: []string{"isd_as", "remote_isd_as", "session_id", "policy_id"},
	}
	SessionStateChangesMeta = MetricMeta{
		Name:   "gateway_session_state_changes",
		Help:   "The number of state changes per session.",
		Labels: []string{"isd_as", "remote_isd_as", "session_id", "policy_id"},
	}
	SessionPathsAvailableMeta = MetricMeta{
		Name:   "gateway_session_paths_available",
		Help:   "Total number of paths available per session policy.",
		Labels: []string{"isd_as", "remote_isd_as", "policy_id", "status"},
	}
	SessionPathChangesMeta = MetricMeta{
		Name:   "gateway_session_path_changes",
		Help:   "Total number of path changes per session policy.",
		Labels: []string{"isd_as", "remote_isd_as", "session_id", "policy_id"},
	}
	RemotesMeta = MetricMeta{
		Name:   "gateway_remotes",
		Help:   "Total number of discovered remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	RemoteChangesMeta = MetricMeta{
		Name:   "gateway_remotes_changes",
		Help:   "The number of times the remotes number changed.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	RemoteDiscoveryErrorsMeta = MetricMeta{
		Name:   "gateway_remote_discovery_errors_total",
		Help:   "Total number of errors discovering remote gateways.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	RoutingChainHealthyMeta = MetricMeta{
		Name:   "gateway_routing_chain_healthiness",
		Help:   "Flag reflecting routing chain healthiness.",
		Labels: []string{"isd_as", "routing_chain_id"},
	}
	RoutingChainAliveSessionsMeta = MetricMeta{
		Name:   "gateway_routing_chain_alive_sessions",
		Help:   "The number of alive sessions associated to the routing chain.",
		Labels: []string{"isd_as", "routing_chain_id"},
	}
	RoutingChainSessionChangesMeta = MetricMeta{
		Name:   "gateway_routing_chain_session_changes",
		Help:   "The number of session changes in the routing chain.",
		Labels: []string{"isd_as", "routing_chain_id"},
	}
	RoutingChainStateChangesMeta = MetricMeta{
		Name:   "gateway_routing_chain_state_changes",
		Help:   "The number of state changes in the routing chain.",
		Labels: []string{"isd_as", "routing_chain_id"},
	}
	PrefixFetchErrorsMeta = MetricMeta{
		Name:   "gateway_prefix_fetch_errors_total",
		Help:   "Total number of errors fetching prefixes.",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	PrefixesAdvertisedMeta = MetricMeta{
		Name:   "gateway_prefixes_advertised",
		Help:   "Total number of advertised IP prefixes (outgoing).",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	PrefixesAcceptedMeta = MetricMeta{
		Name:   "gateway_prefixes_accepted",
		Help:   "Total number of accepted IP prefixes (incoming).",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
	PrefixesRejectedMeta = MetricMeta{
		Name:   "gateway_prefixes_rejected",
		Help:   "Total number of rejected IP prefixes (incoming).",
		Labels: []string{"isd_as", "remote_isd_as"},
	}
)

type MetricMeta struct {
	Name   string
	Help   string
	Labels []string
}

func (mm *MetricMeta) NewCounterVec() *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: mm.Name,
			Help: mm.Help,
		},
		mm.Labels,
	)
}

func (mm *MetricMeta) NewGaugeVec() *prometheus.GaugeVec {
	return promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: mm.Name,
			Help: mm.Help,
		},
		mm.Labels,
	)
}

// Metrics defines the metrics exported by the gateway.
type Metrics struct {
	// Traffic Metrics
	IPPktBytesSentTotal          *prometheus.CounterVec
	IPPktBytesReceivedTotal      *prometheus.CounterVec
	IPPktsSentTotal              *prometheus.CounterVec
	IPPktsReceivedTotal          *prometheus.CounterVec
	IPPktBytesLocalSentTotal     *prometheus.CounterVec
	IPPktBytesLocalReceivedTotal *prometheus.CounterVec
	IPPktsLocalSentTotal         *prometheus.CounterVec
	IPPktsLocalReceivedTotal     *prometheus.CounterVec
	FrameBytesSentTotal          *prometheus.CounterVec
	FrameBytesReceivedTotal      *prometheus.CounterVec
	FramesSentTotal              *prometheus.CounterVec
	FramesReceivedTotal          *prometheus.CounterVec

	// Error Metrics
	FramesDiscardedTotal       *prometheus.CounterVec
	IPPktsDiscardedTotal       *prometheus.CounterVec
	SendExternalErrorsTotal    *prometheus.CounterVec
	SendLocalErrorsTotal       *prometheus.CounterVec
	ReceiveExternalErrorsTotal *prometheus.CounterVec
	ReceiveLocalErrorsTotal    *prometheus.CounterVec

	// Path Monitoring Metrics
	PathsMonitored        *prometheus.GaugeVec
	SessionPathsAvailable *prometheus.GaugeVec
	PathProbesSent        *prometheus.CounterVec
	PathProbesReceived    *prometheus.CounterVec
	PathProbesSendErrors  *prometheus.CounterVec

	// Discovery Metrics
	Remotes               *prometheus.GaugeVec
	RemotesChanges        *prometheus.CounterVec
	RemoteDiscoveryErrors *prometheus.CounterVec
	PrefixFetchErrors     *prometheus.CounterVec
	PrefixesAdvertised    *prometheus.GaugeVec
	PrefixesAccepted      *prometheus.GaugeVec
	PrefixesRejected      *prometheus.GaugeVec

	// SessionMonitor Metrics
	SessionProbes       *prometheus.CounterVec
	SessionProbeReplies *prometheus.CounterVec
	SessionIsHealthy    *prometheus.GaugeVec
	SessionStateChanges *prometheus.CounterVec
	SessionPathChanges  *prometheus.CounterVec

	// Routing Metrics
	RoutingChainHealthy        *prometheus.GaugeVec
	RoutingChainAliveSessions  *prometheus.GaugeVec
	RoutingChainSessionChanges *prometheus.CounterVec
	RoutingChainStateChanges   *prometheus.CounterVec

	// Scion Network Metrics
	SCIONNetworkMetrics    snet.SCIONNetworkMetrics
	SCMPErrors             metrics.Counter
	SCIONPacketConnMetrics snet.SCIONPacketConnMetrics
}

// NewMetrics initializes the metrics for the gateway and registers them with the default registry.
func NewMetrics(ia addr.IA) *Metrics {
	labels := map[string]string{
		"isd_as": ia.String(),
	}
	scionPacketConnMetrics := snetmetrics.NewSCIONPacketConnMetrics()
	return &Metrics{
		IPPktBytesSentTotal: IPPktBytesSentTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		IPPktsSentTotal: IPPktsSentTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		IPPktBytesReceivedTotal: IPPktBytesReceivedTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		IPPktsReceivedTotal: IPPktsReceivedTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		IPPktBytesLocalSentTotal: IPPktBytesLocalSentTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		IPPktsLocalSentTotal: IPPktsLocalSentTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		IPPktBytesLocalReceivedTotal: IPPktBytesLocalReceivedTotalMeta.
			NewCounterVec(),
		IPPktsLocalReceivedTotal: IPPktsLocalReceivedTotalMeta.
			NewCounterVec(),
		FrameBytesSentTotal: FrameBytesSentTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		FramesSentTotal: FramesSentTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		FrameBytesReceivedTotal: FrameBytesReceivedTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		FramesReceivedTotal: FramesReceivedTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		FramesDiscardedTotal: FramesDiscardedTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		IPPktsDiscardedTotal: IPPktsDiscardedTotalMeta.
			NewCounterVec(),
		SendExternalErrorsTotal: SendExternalErrorsTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		SendLocalErrorsTotal: SendLocalErrorsTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		ReceiveExternalErrorsTotal: ReceiveExternalErrorsTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		ReceiveLocalErrorsTotal: ReceiveLocalErrorsTotalMeta.
			NewCounterVec().MustCurryWith(labels),
		PathsMonitored: PathsMonitoredMeta.
			NewGaugeVec().MustCurryWith(labels),
		PathProbesSent: PathProbesSentMeta.
			NewCounterVec().MustCurryWith(labels),
		PathProbesReceived: PathProbesReceivedMeta.
			NewCounterVec().MustCurryWith(labels),
		PathProbesSendErrors: PathProbesSendErrorsMeta.
			NewCounterVec().MustCurryWith(labels),
		SessionIsHealthy: SessionIsHealthyMeta.
			NewGaugeVec().MustCurryWith(labels),
		SessionStateChanges: SessionStateChangesMeta.
			NewCounterVec().MustCurryWith(labels),
		SessionProbes: SessionProbesMeta.
			NewCounterVec().MustCurryWith(labels),
		SessionProbeReplies: SessionProbeRepliesMeta.
			NewCounterVec().MustCurryWith(labels),
		SessionPathsAvailable: SessionPathsAvailableMeta.
			NewGaugeVec().MustCurryWith(labels),
		SessionPathChanges: SessionPathChangesMeta.
			NewCounterVec().MustCurryWith(labels),
		RoutingChainHealthy: RoutingChainHealthyMeta.
			NewGaugeVec().MustCurryWith(labels),
		RoutingChainAliveSessions: RoutingChainAliveSessionsMeta.
			NewGaugeVec().MustCurryWith(labels),
		RoutingChainSessionChanges: RoutingChainSessionChangesMeta.
			NewCounterVec().MustCurryWith(labels),
		RoutingChainStateChanges: RoutingChainStateChangesMeta.
			NewCounterVec().MustCurryWith(labels),
		Remotes: RemotesMeta.
			NewGaugeVec().MustCurryWith(labels),
		RemotesChanges: RemoteChangesMeta.
			NewCounterVec().MustCurryWith(labels),
		RemoteDiscoveryErrors: RemoteDiscoveryErrorsMeta.
			NewCounterVec().MustCurryWith(labels),
		PrefixFetchErrors: PrefixFetchErrorsMeta.
			NewCounterVec().MustCurryWith(labels),
		PrefixesAdvertised: PrefixesAdvertisedMeta.
			NewGaugeVec().MustCurryWith(labels),
		PrefixesAccepted: PrefixesAcceptedMeta.
			NewGaugeVec().MustCurryWith(labels),
		PrefixesRejected: PrefixesRejectedMeta.
			NewGaugeVec().MustCurryWith(labels),
		SCIONNetworkMetrics:    snetmetrics.NewSCIONNetworkMetrics(),
		SCMPErrors:             scionPacketConnMetrics.SCMPErrors,
		SCIONPacketConnMetrics: scionPacketConnMetrics,
	}
}
