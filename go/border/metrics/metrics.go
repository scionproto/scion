// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package metrics defines and exports router metrics to be scraped by
// prometheus.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

// Namespace is the metrics namespace for the border router.
const Namespace = "br"

// Declare prometheus metrics to export.
var (
	// High-level input stats
	InputPkts    *prometheus.CounterVec
	InputBytes   *prometheus.CounterVec
	InputPktSize *prometheus.HistogramVec

	// High-level output stats
	OutputPkts    *prometheus.CounterVec
	OutputBytes   *prometheus.CounterVec
	OutputPktSize *prometheus.HistogramVec

	// Low-level input stats
	InputReads      *prometheus.CounterVec
	InputReadErrors *prometheus.CounterVec
	InputRcvOvfl    *prometheus.GaugeVec
	InputLatency    *prometheus.CounterVec

	// Low-level output stats
	OutputWrites       *prometheus.CounterVec
	OutputWriteErrors  *prometheus.CounterVec
	OutputWriteLatency *prometheus.CounterVec

	// Processing metrics
	ProcessPktTime    *prometheus.CounterVec
	ProcessSockSrcDst *prometheus.CounterVec

	// Misc
	IFState *prometheus.GaugeVec
)

func init() {
	sockLabels := []string{"sock"}

	// Some closures to reduce boiler-plate.
	newCVec := func(name, help string, lNames []string) *prometheus.CounterVec {
		return prom.NewCounterVec(Namespace, "", name, help, lNames)
	}
	newG := func(name, help string) prometheus.Gauge {
		return prom.NewGauge(Namespace, "", name, help)
	}
	newGVec := func(name, help string, lNames []string) *prometheus.GaugeVec {
		return prom.NewGaugeVec(Namespace, "", name, help, lNames)
	}
	newHVec := func(name, help string,
		lNames []string, buckets []float64) *prometheus.HistogramVec {

		return prom.NewHistogramVec(Namespace, "", name, help, lNames, buckets)
	}

	InputPkts = newCVec("input_pkts_total", "Total number of input packets received.", sockLabels)
	InputBytes = newCVec("input_bytes_total", "Total number of input bytes received.", sockLabels)
	InputPktSize = newHVec("input_pkt_size_bytes", "Size of input packets in bytes", sockLabels,
		[]float64{64, 256, 512, 1024, 1280, 1500, 3000, 6000, 9000})

	OutputPkts = newCVec("output_pkts_total", "Total number of output packets sent.", sockLabels)
	OutputBytes = newCVec("output_bytes_total", "Total number of output bytes sent.", sockLabels)
	OutputPktSize = newHVec("output_pkt_size_bytes", "Size of output packets in bytes", sockLabels,
		[]float64{64, 256, 512, 1024, 1280, 1500, 3000, 6000, 9000})

	InputReads = newCVec("input_reads_total", "Total number of input socket reads.", sockLabels)
	InputReadErrors = newCVec(
		"input_read_errors_total", "Total number of input socket read errors.", sockLabels)
	InputLatency = newCVec(
		"input_latency_seconds_total",
		"Total time packets wait in the kernel to be read, in seconds", sockLabels)
	InputRcvOvfl = newGVec(
		"input_overflow_packets_total",
		"Total number of packets dropped by kernel due to receive buffer overflow.", sockLabels)

	OutputWrites = newCVec("output_writes_total", "Number of output socket writes.", sockLabels)
	OutputWriteErrors = newCVec(
		"output_write_errors_total", "Number of output socket write errors.", sockLabels)
	OutputWriteLatency = newCVec(
		"output_write_seconds_total",
		"Total time spent writing output packets, in seconds.", sockLabels)

	ProcessPktTime = newCVec("process_pkt_seconds_total",
		"Total processing time for input packets, in seconds.", sockLabels)
	ProcessSockSrcDst = newCVec("process_pkts_src_dst_total",
		"Total number of packets from one sock to another.", []string{"inSock", "outSock"})

	// border_base_labels is a special metric that always has the value `1`,
	// that is used to add labels to non-br metrics.
	BRLabels := newG("base_labels", "Border base labels.")
	BRLabels.Set(1)
	IFState = newGVec("interface_active", "Interface is active.", sockLabels)
}
