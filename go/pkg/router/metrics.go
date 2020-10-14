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

package router

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics defines the data-plane metrics for the BR.
type Metrics struct {
	InputBytesTotal           *prometheus.CounterVec
	OutputBytesTotal          *prometheus.CounterVec
	InputPacketsTotal         *prometheus.CounterVec
	OutputPacketsTotal        *prometheus.CounterVec
	DroppedPacketsTotal       *prometheus.CounterVec
	InterfaceUp               *prometheus.GaugeVec
	BFDInterfaceStateChanges  *prometheus.CounterVec
	BFDPacketsSent            *prometheus.CounterVec
	BFDPacketsReceived        *prometheus.CounterVec
	SiblingReachable          *prometheus.GaugeVec
	SiblingBFDPacketsSent     *prometheus.CounterVec
	SiblingBFDPacketsReceived *prometheus.CounterVec
	SiblingBFDStateChanges    *prometheus.CounterVec
}

// NewMetrics initializes the metrics for the Border Router, and registers them
// with the default registry.
func NewMetrics() *Metrics {
	return &Metrics{
		InputBytesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_input_bytes_total",
				Help: "Total number of bytes received",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		OutputBytesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_output_bytes_total",
				Help: "Total number of bytes sent.",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		InputPacketsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_input_pkts_total",
				Help: "Total number of packets received",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		OutputPacketsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_output_pkts_total",
				Help: "Total number of packets sent.",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		DroppedPacketsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_dropped_pkts_total",
				Help: "Total number of packets dropped by the router. This metric reports " +
					"the number of packets that were dropped because of errors.",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		InterfaceUp: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "router_interface_up",
				Help: "Either zero or one depending on whether the interface is up.",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		BFDInterfaceStateChanges: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_bfd_state_changes_total",
				Help: "Total number of BFD state changes.",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		BFDPacketsSent: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_bfd_sent_packets_total",
				Help: "Number of BFD packets sent.",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		BFDPacketsReceived: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_bfd_received_packets_total",
				Help: "Number of BFD packets received.",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		SiblingReachable: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "router_sibling_reachable",
				Help: "Either zero or one depending on whether a sibling router " +
					"instance is reachable.",
			},
			[]string{"sibling", "isd_as"},
		),
		SiblingBFDPacketsSent: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_bfd_sent_sibling_packets_total",
				Help: "Number of BFD packets sent to sibling router instance.",
			},
			[]string{"sibling", "isd_as"},
		),
		SiblingBFDPacketsReceived: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_bfd_received_sibling_packets_total",
				Help: "Number of BFD packets received from sibling router instance.",
			},
			[]string{"sibling", "isd_as"},
		),
		SiblingBFDStateChanges: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_bfd_sibling_state_changes_total",
				Help: "Total number of BFD state changes for sibling router instances",
			},
			[]string{"sibling", "isd_as"},
		),
	}
}
