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

type output struct {
	// High-level output stats
	pkts    *prometheus.CounterVec
	bytes   *prometheus.CounterVec
	pktSize *prometheus.HistogramVec

	// Low-level output stats
	writes      *prometheus.CounterVec
	writeErrors *prometheus.CounterVec
	duration    *prometheus.CounterVec
}

func newOutput() output {
	sub := "output"
	l := IntfLabels{}.Labels()
	return output{
		pkts: prom.NewCounterVec(Namespace, sub,
			"pkts_total", "Total number of packets sent.", l),
		bytes: prom.NewCounterVec(Namespace, sub,
			"bytes_total", "Total number of bytes sent.", l),
		pktSize: prom.NewHistogramVec(Namespace, sub,
			"pkt_size_bytes", "Size of output packets in bytes", l,
			[]float64{64, 256, 512, 1024, 1280, 1500, 3000, 6000, 9000}),

		writes: prom.NewCounterVec(Namespace, sub,
			"writes_total", "Total number of output socket writes.", l),
		writeErrors: prom.NewCounterVec(Namespace, sub,
			"write_errors_total", "Total number of output socket write errors.", l),
		duration: prom.NewCounterVec(Namespace, sub,
			"write_duration_seconds_total",
			"Total time spent writing packets to the kernel, in seconds.", l),
	}
}

// Pkts returns the counter for the given label set.
func (o *output) Pkts(l IntfLabels) prometheus.Counter {
	return o.pkts.WithLabelValues(l.Values()...)
}

// Bytes returns the counter for the given label set.
func (o *output) Bytes(l IntfLabels) prometheus.Counter {
	return o.bytes.WithLabelValues(l.Values()...)
}

// PktSize returns the observer for the given label set.
func (o *output) PktSize(l IntfLabels) prometheus.Observer {
	return o.pktSize.WithLabelValues(l.Values()...)
}

// Writes returns the counter for the given label set.
func (o *output) Writes(l IntfLabels) prometheus.Counter {
	return o.writes.WithLabelValues(l.Values()...)
}

// WriteErrors returns the counter for the given label set.
func (o *output) WriteErrors(l IntfLabels) prometheus.Counter {
	return o.writeErrors.WithLabelValues(l.Values()...)
}

// Duration returns the counter for the given label set.
func (o *output) Duration(l IntfLabels) prometheus.Counter {
	return o.duration.WithLabelValues(l.Values()...)
}
