// Copyright 2017 ETH Zurich
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

package ringbuf

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

var WriteCalls *prometheus.CounterVec
var ReadCalls *prometheus.CounterVec
var WritesBlocked *prometheus.CounterVec
var ReadsBlocked *prometheus.CounterVec
var WriteEntries *prometheus.HistogramVec
var ReadEntries *prometheus.HistogramVec
var MaxEntries *prometheus.GaugeVec
var UsedEntries *prometheus.GaugeVec

func InitMetrics(namespace string, constLabels prometheus.Labels, labelNames []string) {
	lNames := append(labelNames, "desc")
	newCVec := func(name, help string) *prometheus.CounterVec {
		v := prom.NewCounterVec(namespace, "ringbuf", name, help, constLabels, lNames)
		prometheus.MustRegister(v)
		return v
	}
	newGVec := func(name, help string) *prometheus.GaugeVec {
		v := prom.NewGaugeVec(namespace, "ringbuf", name, help, constLabels, lNames)
		prometheus.MustRegister(v)
		return v
	}
	newHVec := func(name, help string, buckets []float64) *prometheus.HistogramVec {
		v := prom.NewHistogramVec(namespace, "ringbuf", name, help, constLabels, lNames, buckets)
		prometheus.MustRegister(v)
		return v
	}
	WriteCalls = newCVec("write_calls_total", "Number of calls to Write.")
	ReadCalls = newCVec("read_calls_total", "Number of calls to Read.")
	WritesBlocked = newCVec("writes_blocked_total", "Number of blocked Writes.")
	ReadsBlocked = newCVec("reads_blocked_total", "Number of blocked Reads.")
	WriteEntries = newHVec("write_entries", "Number of written entries.",
		prometheus.ExponentialBuckets(1, 2, 8))
	ReadEntries = newHVec("read_entries", "Number of read entries.",
		prometheus.ExponentialBuckets(1, 2, 8))
	MaxEntries = newGVec("max_entries", "Maximum number of entries.")
	UsedEntries = newGVec("used_entries", "Number of used entries.")
}

type metrics struct {
	writeCalls    prometheus.Counter
	readCalls     prometheus.Counter
	writesBlocked prometheus.Counter
	readsBlocked  prometheus.Counter
	writeEntries  prometheus.Histogram
	readEntries   prometheus.Histogram
	maxEntries    prometheus.Gauge
	usedEntries   prometheus.Gauge
}

func newMetrics(desc string, labels prometheus.Labels) *metrics {
	l := prom.CopyLabels(labels)
	l["desc"] = desc
	return &metrics{
		writeCalls:    WriteCalls.With(l),
		readCalls:     ReadCalls.With(l),
		writesBlocked: WritesBlocked.With(l),
		readsBlocked:  ReadsBlocked.With(l),
		writeEntries:  WriteEntries.With(l),
		readEntries:   ReadEntries.With(l),
		maxEntries:    MaxEntries.With(l),
		usedEntries:   UsedEntries.With(l),
	}
}
