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
)

// These are the metrics that should be exposed by any gateway implementation.
var (
	IPPktBytesSentTotalMeta = MetricMeta{
		Name:   "gateway_ippkt_bytes_sent_total",
		Help:   "Total IP packet bytes sent to remote gateways.",
		Labels: []string{"remote_isd_as", "policy_id"},
	}
	IPPktsSentTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_sent_total",
		Help:   "Total number of IP packets sent to remote gateways.",
		Labels: []string{"remote_isd_as", "policy_id"},
	}
	IPPktBytesReceivedTotalMeta = MetricMeta{
		Name:   "gateway_ippkt_bytes_received_total",
		Help:   "Total IP packet bytes received from remote gateways.",
		Labels: []string{"remote_isd_as"},
	}
	IPPktsReceivedTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_received_total",
		Help:   "Total number of IP packets received from remote gateways.",
		Labels: []string{"remote_isd_as"},
	}
	IPPktBytesLocalSentTotalMeta = MetricMeta{
		Name:   "gateway_ippkt_bytes_local_sent_total",
		Help:   "Total IP packet bytes sent to the local network.",
		Labels: []string{},
	}
	IPPktsLocalSentTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_local_sent_total",
		Help:   "Total number of IP packets sent to the local network.",
		Labels: []string{},
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
		Labels: []string{"remote_isd_as", "policy_id"},
	}
	FramesSentTotalMeta = MetricMeta{
		Name:   "gateway_frames_sent_total",
		Help:   "Total number of frames sent to remote gateways.",
		Labels: []string{"remote_isd_as", "policy_id"},
	}
	FrameBytesReceivedTotalMeta = MetricMeta{
		Name:   "gateway_frame_bytes_received_total",
		Help:   "gateway_frame_bytes_received_total",
		Labels: []string{"remote_isd_as"},
	}
	FramesReceivedTotalMeta = MetricMeta{
		Name:   "gateway_frames_received_total",
		Help:   "Total number of frames received from remote gateways.",
		Labels: []string{"remote_isd_as"},
	}
	FramesDiscardedTotalMeta = MetricMeta{
		Name:   "gateway_frames_discarded_total",
		Help:   "Total number of discarded frames received from remote gateways.",
		Labels: []string{"remote_isd_as", "reason"},
	}
	IPPktsDiscardedTotalMeta = MetricMeta{
		Name:   "gateway_ippkts_discarded_total",
		Help:   "Total number of discarded IP packets received from the local network.",
		Labels: []string{"reason"},
	}
	SendExternalErrorsTotalMeta = MetricMeta{
		Name:   "gateway_send_external_errors_total",
		Help:   "Total number of errors when sending frames to the network (WAN).",
		Labels: []string{},
	}
	SendLocalErrorsTotalMeta = MetricMeta{
		Name:   "gateway_send_local_errors_total",
		Help:   "Total number of errors when sending IP packets to the network (LAN).",
		Labels: []string{},
	}
	ReceiveExternalErrorsTotalMeta = MetricMeta{
		Name:   "gateway_receive_external_errors_total",
		Help:   "Total number of errors when receiving frames from the network (WAN).",
		Labels: []string{},
	}
	ReceiveLocalErrorsTotalMeta = MetricMeta{
		Name:   "gateway_receive_local_errors_total",
		Help:   "Total number of errors when receiving IP packets from the network (LAN).",
		Labels: []string{},
	}
	PathsMonitoredMeta = MetricMeta{
		Name:   "gateway_paths_monitored",
		Help:   "Total number of paths being monitored by the gateway.",
		Labels: []string{"remote_isd_as"},
	}
	PathProbesSentMeta = MetricMeta{
		Name:   "gateway_path_probes_sent",
		Help:   "Number of path probes being sent.",
		Labels: []string{"remote_isd_as"},
	}
	PathProbesReceivedMeta = MetricMeta{
		Name:   "gateway_path_probes_received",
		Help:   "Number of replies to the path probes being received.",
		Labels: []string{"remote_isd_as"},
	}
	SessionProbesMeta = MetricMeta{
		Name:   "gateway_session_probes",
		Help:   "Number of probes sent per session.",
		Labels: []string{"remote_isd_as", "session_id", "policy_id"},
	}
	SessionProbeRepliesMeta = MetricMeta{
		Name:   "gateway_session_probe_replies",
		Help:   "Number of probes received per session.",
		Labels: []string{"remote_isd_as", "session_id", "policy_id"},
	}
	SessionIsHealthyMeta = MetricMeta{
		Name:   "gateway_session_is_healthy",
		Help:   "Flag reflecting session healthiness.",
		Labels: []string{"remote_isd_as", "session_id", "policy_id"},
	}
	SessionPathsAvailableMeta = MetricMeta{
		Name:   "gateway_session_paths_available",
		Help:   "Total number of paths available per session policy.",
		Labels: []string{"remote_isd_as", "policy_id", "status"},
	}
	RemotesMeta = MetricMeta{
		Name:   "gateway_remotes",
		Help:   "Total number of discovered remote gateways.",
		Labels: []string{"remote_isd_as"},
	}
	PrefixesAdvertisedMeta = MetricMeta{
		Name:   "gateway_prefixes_advertised",
		Help:   "Total number of advertised IP prefixes (outgoing).",
		Labels: []string{"remote_isd_as"},
	}
	PrefixesAcceptedMeta = MetricMeta{
		Name:   "gateway_prefixes_accepted",
		Help:   "Total number of accepted IP prefixes (incoming).",
		Labels: []string{"remote_isd_as"},
	}
	PrefixesRejectedMeta = MetricMeta{
		Name:   "gateway_prefixes_rejected",
		Help:   "Total number of rejected IP prefixes (incoming).",
		Labels: []string{"remote_isd_as"},
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

	// Discovery Metrics
	Remotes            *prometheus.GaugeVec
	PrefixesAdvertised *prometheus.GaugeVec
	PrefixesAccepted   *prometheus.GaugeVec
	PrefixesRejected   *prometheus.GaugeVec

	// SessionMonitor Metrics
	SessionProbes       *prometheus.CounterVec
	SessionProbeReplies *prometheus.CounterVec
	SessionIsHealthy    *prometheus.GaugeVec
}

// NewMetrics initializes the metrics for the gateway and registers them with the default registry.
func NewMetrics() *Metrics {
	return &Metrics{
		IPPktBytesSentTotal:          IPPktBytesSentTotalMeta.NewCounterVec(),
		IPPktsSentTotal:              IPPktsSentTotalMeta.NewCounterVec(),
		IPPktBytesReceivedTotal:      IPPktBytesReceivedTotalMeta.NewCounterVec(),
		IPPktsReceivedTotal:          IPPktsReceivedTotalMeta.NewCounterVec(),
		IPPktBytesLocalSentTotal:     IPPktBytesLocalSentTotalMeta.NewCounterVec(),
		IPPktsLocalSentTotal:         IPPktsLocalSentTotalMeta.NewCounterVec(),
		IPPktBytesLocalReceivedTotal: IPPktBytesLocalReceivedTotalMeta.NewCounterVec(),
		IPPktsLocalReceivedTotal:     IPPktsLocalReceivedTotalMeta.NewCounterVec(),
		FrameBytesSentTotal:          FrameBytesSentTotalMeta.NewCounterVec(),
		FramesSentTotal:              FramesSentTotalMeta.NewCounterVec(),
		FrameBytesReceivedTotal:      FrameBytesReceivedTotalMeta.NewCounterVec(),
		FramesReceivedTotal:          FramesReceivedTotalMeta.NewCounterVec(),
		FramesDiscardedTotal:         FramesDiscardedTotalMeta.NewCounterVec(),
		IPPktsDiscardedTotal:         IPPktsDiscardedTotalMeta.NewCounterVec(),
		SendExternalErrorsTotal:      SendExternalErrorsTotalMeta.NewCounterVec(),
		SendLocalErrorsTotal:         SendLocalErrorsTotalMeta.NewCounterVec(),
		ReceiveExternalErrorsTotal:   ReceiveExternalErrorsTotalMeta.NewCounterVec(),
		ReceiveLocalErrorsTotal:      ReceiveLocalErrorsTotalMeta.NewCounterVec(),
		PathsMonitored:               PathsMonitoredMeta.NewGaugeVec(),
		PathProbesSent:               PathProbesSentMeta.NewCounterVec(),
		PathProbesReceived:           PathProbesReceivedMeta.NewCounterVec(),
		SessionIsHealthy:             SessionIsHealthyMeta.NewGaugeVec(),
		SessionProbes:                SessionProbesMeta.NewCounterVec(),
		SessionProbeReplies:          SessionProbeRepliesMeta.NewCounterVec(),
		SessionPathsAvailable:        SessionPathsAvailableMeta.NewGaugeVec(),
		Remotes:                      RemotesMeta.NewGaugeVec(),
		PrefixesAdvertised:           PrefixesAdvertisedMeta.NewGaugeVec(),
		PrefixesAccepted:             PrefixesAcceptedMeta.NewGaugeVec(),
		PrefixesRejected:             PrefixesRejectedMeta.NewGaugeVec(),
	}
}
