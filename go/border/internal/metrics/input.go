// Copyright 2019 Anapaya Systems
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

type input struct {
	// High-level input stats
	pkts    *prometheus.CounterVec
	bytes   *prometheus.CounterVec
	pktSize *prometheus.HistogramVec

	// Low-level input stats
	reads      *prometheus.CounterVec
	readErrors *prometheus.CounterVec
	rcvOvfl    *prometheus.GaugeVec
	latency    *prometheus.CounterVec
}

func newInput() input {
	sub := "input"
	l := IntfLabels{}.Labels()
	return input{
		pkts: prom.NewCounterVec(Namespace, sub,
			"pkts_total", "Total number of packets received.", l),
		bytes: prom.NewCounterVec(Namespace, sub,
			"bytes_total", "Total number of bytes received.", l),
		pktSize: prom.NewHistogramVec(Namespace, sub,
			"pkt_size_bytes", "Size of input packets in bytes", l,
			[]float64{64, 256, 512, 1024, 1280, 1500, 3000, 6000, 9000}),

		reads: prom.NewCounterVec(Namespace, sub,
			"reads_total", "Total number of input socket reads.", l),
		readErrors: prom.NewCounterVec(Namespace, sub,
			"read_errors_total", "Total number of input socket read errors.", l),
		rcvOvfl: prom.NewGaugeVec(Namespace, sub,
			"overflow_packets_total",
			"Total number of packets dropped by kernel due to receive buffer overflow.", l),
		latency: prom.NewCounterVec(Namespace, sub,
			"read_latency_seconds_total",
			"Total time packets wait in the kernel to be read, in seconds", l),
	}
}

// Pkts returns the counter for the given label set.
func (in *input) Pkts(l IntfLabels) prometheus.Counter {
	return in.pkts.WithLabelValues(l.Values()...)
}

// Bytes returns the counter for the given label set.
func (in *input) Bytes(l IntfLabels) prometheus.Counter {
	return in.bytes.WithLabelValues(l.Values()...)
}

// PktSize returns the observer for the given label set.
func (in *input) PktSize(l IntfLabels) prometheus.Observer {
	return in.pktSize.WithLabelValues(l.Values()...)
}

// Reads returns the counter for the given label set.
func (in *input) Reads(l IntfLabels) prometheus.Counter {
	return in.reads.WithLabelValues(l.Values()...)
}

// ReadErrors returns the counter for the given label set.
func (in *input) ReadErrors(l IntfLabels) prometheus.Counter {
	return in.readErrors.WithLabelValues(l.Values()...)
}

// RcvOvfl returns the gauge for the given label set.
func (in *input) RcvOvfl(l IntfLabels) prometheus.Gauge {
	return in.rcvOvfl.WithLabelValues(l.Values()...)
}

// Latency returns the counter for the given label set.
func (in *input) Latency(l IntfLabels) prometheus.Counter {
	return in.latency.WithLabelValues(l.Values()...)
}
