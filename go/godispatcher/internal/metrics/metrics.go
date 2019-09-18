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
	"github.com/scionproto/scion/go/lib/ringbuf"
)

// Namespace is the metrics namespace for the dispatcher.
const Namespace = "disp"

// Label descriptions
const (
	IncomingPacketOutcome = "incoming_packet_outcome"
	OpenConnectionType    = "open_connection_type"
)

// Packet outcome labels
const (
	PacketOutcomeParseError    = "parse_error"
	PacketOutcomeRouteNotFound = "route_not_found"
	PacketOutcomeOk            = "ok"
)

var (
	OutgoingPacketsTotal prometheus.Counter
	IncomingBytesTotal   prometheus.Counter
	OutgoingBytesTotal   prometheus.Counter
	IncomingPackets      *prometheus.CounterVec
	OpenSockets          *prometheus.GaugeVec
)

// GetOpenConnectionLabel returns an SVC address string representation for sockets
// that are opened on an SVC address, or a different string otherwise.
func GetOpenConnectionLabel(svc addr.HostSVC) string {
	if svc == addr.SvcNone {
		return "no_svc"
	}
	return svc.BaseString()
}

func init() {
	ringbuf.InitMetrics(Namespace, nil)
	OutgoingBytesTotal = prom.NewCounter(Namespace, "", "outgoing_bytes_total",
		"Total bytes sent on the network.")
	OutgoingPacketsTotal = prom.NewCounter(Namespace, "", "outgoing_packets_total",
		"Total packets sent on the network.")
	IncomingBytesTotal = prom.NewCounter(Namespace, "", "incoming_bytes_total",
		"Total bytes received from the network irrespective of packet outcome.")
	IncomingPackets = prom.NewCounterVec(Namespace, "", "incoming_packets_total",
		"Total packets received from the network.", []string{IncomingPacketOutcome})
	OpenSockets = prom.NewGaugeVec(Namespace, "", "open_application_connections",
		"Number of sockets currently opened by applications.", []string{OpenConnectionType})
}
