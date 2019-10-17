// Copyright 2019 ETH Zurich
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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/prom"
)

// Namespace is the metrics namespace for the dispatcher.
const Namespace = "disp"

// Packet outcome labels
const (
	PacketOutcomeParseError    = "parse_error"
	PacketOutcomeRouteNotFound = "route_not_found"
	PacketOutcomeOk            = "ok"
)

var (
	// M exposes all the initialized metrics for this package.
	M = newMetrics()
)

// IncomingPacket contains the labels for incoming packet metrics.
type IncomingPacket struct {
	Outcome string
}

// Labels returns the list of labels.
func (l IncomingPacket) Labels() []string {
	return []string{"incoming_packet_outcome"}
}

// Values returns the label values in the order defined by Labels.
func (l IncomingPacket) Values() []string {
	return []string{l.Outcome}
}

// SVC contains the labels for SVC-related metrics.
type SVC struct {
	Type string
}

// Labels returns the list of labels.
func (l SVC) Labels() []string {
	return []string{"type"}
}

// Values returns the label values in the order defined by Labels.
func (l SVC) Values() []string {
	return []string{l.Type}
}

// SCMP contains the labels for SCMP-related metrics.
type SCMP struct {
	Class string
	Type  string
}

// Labels returns the list of labels.
func (l SCMP) Labels() []string {
	return []string{"class", "type"}
}

// Values returns the label values in the order defined by Labels.
func (l SCMP) Values() []string {
	return []string{"class", "type"}
}

type metrics struct {
	netWriteBytes      prometheus.Counter
	netWritePkts       prometheus.Counter
	netWriteErrors     prometheus.Counter
	netReadBytes       prometheus.Counter
	netReadPkts        *prometheus.CounterVec
	netReadParseErrors prometheus.Counter
	openSockets        *prometheus.GaugeVec
	appConnErrors      prometheus.Counter
	scmpReadPkts       *prometheus.CounterVec
	scmpWritePkts      *prometheus.CounterVec
	appNotFoundErrors  prometheus.Counter
	appWriteSVCPkts    *prometheus.CounterVec
	netReadOverflows   prometheus.Counter
}

func newMetrics() metrics {
	return metrics{
		netWriteBytes: prom.NewCounter(Namespace, "", "net_write_total_bytes",
			"Total bytes sent on the network."),
		netWritePkts: prom.NewCounter(Namespace, "", "net_write_total_pkts",
			"Total packets sent on the network."),
		netWriteErrors: prom.NewCounter(Namespace, "", "net_write_error_total",
			"Network packet send errors"),
		netReadBytes: prom.NewCounter(Namespace, "", "net_read_total_bytes",
			"Total bytes received from the network irrespective of packet outcome."),
		netReadPkts: prom.NewCounterVec(Namespace, "", "net_read_total_pkts",
			"Total packets received from the network.", IncomingPacket{}.Labels()),
		netReadParseErrors: prom.NewCounter(Namespace, "", "net_read_parse_errors_total",
			"Total network packet parse error"),
		openSockets: prom.NewGaugeVec(Namespace, "", "app_sockets_open",
			"Number of sockets currently opened by applications.", SVC{}.Labels()),
		appConnErrors: prom.NewCounter(Namespace, "", "app_conn_error_total",
			"Application socket registration errors"),
		scmpReadPkts: prom.NewCounterVec(Namespace, "", "scmp_read_total_pkts",
			"Total SCMP packets received from the network.", SCMP{}.Labels()),
		scmpWritePkts: prom.NewCounterVec(Namespace, "", "scmp_write_total_pkts",
			"Total SCMP packets received from the network.", SCMP{}.Labels()),
		appNotFoundErrors: prom.NewCounter(Namespace, "", "app_not_found_total",
			"Number of packets for which the destination application was not found."),
		appWriteSVCPkts: prom.NewCounterVec(Namespace, "", "app_write_svc_total_pkts",
			"Total SVC packets delivered to applications", SVC{}.Labels()),
		netReadOverflows: prom.NewCounter(Namespace, "", "net_read_overflow_total_pkts",
			"Total ingress packets that were dropped on the OS socket"),
	}
}

// GetOpenConnectionLabel returns an SVC address string representation for sockets
// that are opened on an SVC address, or a different string otherwise.
func GetOpenConnectionLabel(svc addr.HostSVC) string {
	if svc == addr.SvcNone {
		return "no_svc"
	}
	return svc.BaseString()
}

func (m metrics) NetWriteBytes() prometheus.Counter {
	return m.netWriteBytes
}

func (m metrics) NetWritePkts() prometheus.Counter {
	return m.netWritePkts
}

func (m metrics) NetReadBytes() prometheus.Counter {
	return m.netReadBytes
}

func (m metrics) NetReadPkts(labels IncomingPacket) prometheus.Counter {
	return m.netReadPkts.WithLabelValues(labels.Values()...)
}

func (m metrics) NetReadParseErrors() prometheus.Counter {
	return m.netReadParseErrors
}

func (m metrics) OpenSockets(labels SVC) prometheus.Gauge {
	return m.openSockets.WithLabelValues(labels.Values()...)
}

func (m metrics) AppConnErrors() prometheus.Counter {
	return m.appConnErrors
}

func (m metrics) NetWriteErrors() prometheus.Counter {
	return m.netWriteErrors
}

// SCMPReadPackets returns the metrics counters for SCMP packets read from the network.
func (m metrics) SCMPReadPkts(labels SCMP) prometheus.Counter {
	return m.scmpReadPkts.WithLabelValues(labels.Values()...)
}

// SCMPWritePkts returns the metrics counters for SCMP packets written to the network.
func (m metrics) SCMPWritePkts(labels SCMP) prometheus.Counter {
	return m.scmpWritePkts.WithLabelValues(labels.Values()...)
}

func (m metrics) AppNotFoundErrors() prometheus.Counter {
	return m.appNotFoundErrors
}

func (m metrics) AppWriteSVCPkts(labels SVC) prometheus.Counter {
	return m.appWriteSVCPkts.WithLabelValues(labels.Values()...)
}

func (m metrics) NetReadOverflows() prometheus.Counter {
	return m.netReadOverflows
}
