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
	InputBytesTotal          *prometheus.CounterVec
	OutputBytesTotal         *prometheus.CounterVec
	InputPacketsTotal        *prometheus.CounterVec
	OutputPacketsTotal       *prometheus.CounterVec
	InputErrorsTotal         *prometheus.CounterVec
	OutputErrorsTotal        *prometheus.CounterVec
	InputDroppedPacketsTotal *prometheus.CounterVec
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
		InputErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_input_read_errors_total",
				Help: "Total number of input socket read errors",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		OutputErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_output_write_errors_total",
				Help: "Total number of output socket write errors.",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
		InputDroppedPacketsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_input_dropped_pkts_total",
				Help: "Total number of packets dropped by kernel due to receive buffer overflow",
			},
			[]string{"interface", "isd_as", "neighbor_isd_as"},
		),
	}
}
