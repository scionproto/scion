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

type RingbufLabels struct {
	RingID string
}

func (l *RingbufLabels) Labels() []string {
	return []string{"ring_id"}
}

func (l *RingbufLabels) Values() []string {
	return []string{l.RingID}
}

type ringbuf struct {
	writeCalls    *prometheus.CounterVec
	readCalls     *prometheus.CounterVec
	writesBlocked *prometheus.CounterVec
	readsBlocked  *prometheus.CounterVec
	writeEntries  *prometheus.HistogramVec
	readEntries   *prometheus.HistogramVec
	maxEntries    *prometheus.GaugeVec
	usedEntries   *prometheus.GaugeVec
}

func newRingbuf() ringbuf {
	rl := &RingbufLabels{}
	return ringbuf{
		writeCalls: prom.NewCounterVecWithLabels(Namespace, "",
			"write_calls_total", "Number of calls to Write.", rl),
		readCalls: prom.NewCounterVecWithLabels(Namespace, "",
			"read_calls_total", "Number of calls to Read.", rl),
		writesBlocked: prom.NewCounterVecWithLabels(Namespace, "",
			"writes_blocked_total", "Number of blocked Writes.", rl),
		readsBlocked: prom.NewCounterVecWithLabels(Namespace, "",
			"reads_blocked_total", "Number of blocked Reads.", rl),
		writeEntries: prom.NewHistogramVecWithLabels(Namespace, "",
			"write_entries", "Number of written entries.", rl,
			prometheus.ExponentialBuckets(1, 2, 8)),
		readEntries: prom.NewHistogramVecWithLabels(Namespace, "",
			"read_entries", "Number of read entries.", rl,
			prometheus.ExponentialBuckets(1, 2, 8)),
		maxEntries: prom.NewGaugeVecWithLabels(Namespace, "",
			"max_entries", "Maximum number of entries.", rl),
		usedEntries: prom.NewGaugeVecWithLabels(Namespace, "",
			"used_entries", "Number of used entries.", rl),
	}
}

type Ringbuf struct {
	WriteCalls    prometheus.Counter
	ReadCalls     prometheus.Counter
	WritesBlocked prometheus.Counter
	ReadsBlocked  prometheus.Counter
	WriteEntries  prometheus.Observer
	ReadEntries   prometheus.Observer
	MaxEntries    prometheus.Gauge
	UsedEntries   prometheus.Gauge
}

func NewRingbuf(l *RingbufLabels) Ringbuf {
	return Ringbuf{
		WriteCalls:    rb.writeCalls.WithLabelValues(l.Values()...),
		ReadCalls:     rb.readCalls.WithLabelValues(l.Values()...),
		WritesBlocked: rb.writesBlocked.WithLabelValues(l.Values()...),
		ReadsBlocked:  rb.readsBlocked.WithLabelValues(l.Values()...),
		WriteEntries:  rb.writeEntries.WithLabelValues(l.Values()...),
		ReadEntries:   rb.readEntries.WithLabelValues(l.Values()...),
		MaxEntries:    rb.maxEntries.WithLabelValues(l.Values()...),
		UsedEntries:   rb.usedEntries.WithLabelValues(l.Values()...),
	}
}
