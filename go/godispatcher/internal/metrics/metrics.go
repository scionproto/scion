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

	"github.com/scionproto/scion/go/lib/prom"
)

// Namespace is the metrics namespace for the dispatcher.
const Namespace = "disp"

// Packet result labels
const (
	PacketResultParseError    = "parse_error"
	PacketResultRouteNotFound = "route_not_found"
	PacketResultOk            = "ok"
)

var (
	// M exposes all the initialized metrics for this package.
	M = newMetrics()
)

// IncomingPacket contains the labels for incoming packet metrics.
type IncomingPacket struct {
	Result string
}

// Labels returns the list of labels.
func (l IncomingPacket) Labels() []string {
	return []string{"incoming_packet_result"}
}

// Values returns the label values in the order defined by Labels.
func (l IncomingPacket) Values() []string {
	return []string{l.Result}
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
	appWriteBytes      prometheus.Counter
	appWritePkts       prometheus.Counter
	appWriteErrors     prometheus.Counter
	appReadBytes       prometheus.Counter
	appReadPkts        prometheus.Counter
	appReadErrors      prometheus.Counter
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
		netWriteBytes: prom.NewCounter(Namespace, "", "net_write_bytes_total",
			"Total bytes sent on the network."),
		netWritePkts: prom.NewCounter(Namespace, "", "net_write_pkts_total",
			"Total packets sent on the network."),
		netWriteErrors: prom.NewCounter(Namespace, "", "net_write_errors_total",
			"Network packet send errors"),
		netReadBytes: prom.NewCounter(Namespace, "", "net_read_bytes_total",
			"Total bytes received from the network irrespective of packet outcome."),
		netReadPkts: prom.NewCounterVecWithLabels(Namespace, "", "net_read_pkts_total",
			"Total packets received from the network.", IncomingPacket{}),
		netReadParseErrors: prom.NewCounter(Namespace, "", "net_read_parse_errors_total",
			"Total network packet parse error"),
		appWriteBytes: prom.NewCounter(Namespace, "", "app_write_bytes_total",
			"Total bytes sent to applications."),
		appWritePkts: prom.NewCounter(Namespace, "", "app_write_pkts_total",
			"Total packets sent to applications."),
		appWriteErrors: prom.NewCounter(Namespace, "", "app_write_errors_total",
			"Send packet to applications errors."),
		appReadBytes: prom.NewCounter(Namespace, "", "app_read_bytes_total",
			"Total bytes read from applications."),
		appReadPkts: prom.NewCounter(Namespace, "", "app_read_pkts_total",
			"Total packets read from applications"),
		appReadErrors: prom.NewCounter(Namespace, "", "app_read_errors_total",
			"Total errors when reading packets from applications."),
		openSockets: prom.NewGaugeVecWithLabels(Namespace, "", "app_sockets_open",
			"Number of sockets currently opened by applications.", SVC{}),
		appConnErrors: prom.NewCounter(Namespace, "", "app_conn_reg_errors_total",
			"Application socket registration errors"),
		scmpReadPkts: prom.NewCounterVecWithLabels(Namespace, "", "scmp_read_pkts_total",
			"Total SCMP packets received from the network.", SCMP{}),
		scmpWritePkts: prom.NewCounterVecWithLabels(Namespace, "", "scmp_write_pkts_total",
			"Total SCMP packets received from the network.", SCMP{}),
		appNotFoundErrors: prom.NewCounter(Namespace, "", "app_not_found_errors_total",
			"Number of packets for which the destination application was not found."),
		appWriteSVCPkts: prom.NewCounterVecWithLabels(Namespace, "", "app_write_svc_pkts_total",
			"Total SVC packets delivered to applications", SVC{}),
		netReadOverflows: prom.NewCounter(Namespace, "", "net_read_overflow_pkts_total",
			"Total ingress packets that were dropped on the OS socket"),
	}
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

func (m metrics) AppWriteBytes() prometheus.Counter {
	return m.appWriteBytes
}

func (m metrics) AppWritePkts() prometheus.Counter {
	return m.appWritePkts
}

func (m metrics) AppWriteErrors() prometheus.Counter {
	return m.appWriteErrors
}

func (m metrics) AppReadBytes() prometheus.Counter {
	return m.appReadBytes
}

func (m metrics) AppReadPkts() prometheus.Counter {
	return m.appReadPkts
}

func (m metrics) AppReadErrors() prometheus.Counter {
	return m.appReadErrors
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
