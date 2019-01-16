// Copyright 2017 ETH Zurich
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

package ringbuf

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

var (
	WriteCalls    *prometheus.CounterVec
	ReadCalls     *prometheus.CounterVec
	WritesBlocked *prometheus.CounterVec
	ReadsBlocked  *prometheus.CounterVec
	WriteEntries  *prometheus.HistogramVec
	ReadEntries   *prometheus.HistogramVec
	MaxEntries    *prometheus.GaugeVec
	UsedEntries   *prometheus.GaugeVec
)

func InitMetrics(namespace string, labelNames []string) {
	lNames := append(labelNames, "desc")
	newCVec := func(name, help string) *prometheus.CounterVec {
		return prom.NewCounterVec(namespace, "ringbuf", name, help, lNames)
	}
	newGVec := func(name, help string) *prometheus.GaugeVec {
		return prom.NewGaugeVec(namespace, "ringbuf", name, help, lNames)
	}
	newHVec := func(name, help string, buckets []float64) *prometheus.HistogramVec {
		return prom.NewHistogramVec(namespace, "ringbuf", name, help, lNames, buckets)
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
	writeEntries  prometheus.Observer
	readEntries   prometheus.Observer
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
