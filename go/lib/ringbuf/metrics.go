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
)

type metrics struct {
	writeCalls   prometheus.Counter
	readCalls    prometheus.Counter
	writeEntries prometheus.Counter
	readEntries  prometheus.Counter
}

func newMetrics(desc string, labels prometheus.Labels) *metrics {
	l := copyLabels(labels)
	l["desc"] = desc
	return &metrics{
		writeCalls:   WriteCalls.With(l),
		readCalls:    ReadCalls.With(l),
		writeEntries: WriteEntries.With(l),
		readEntries:  ReadEntries.With(l),
	}
}

func copyLabels(labels prometheus.Labels) prometheus.Labels {
	l := make(prometheus.Labels)
	for k, v := range labels {
		l[k] = v
	}
	return l
}

var WriteCalls *prometheus.CounterVec
var ReadCalls *prometheus.CounterVec
var WriteEntries *prometheus.CounterVec
var ReadEntries *prometheus.CounterVec

func InitMetrics(namespace string) {
	WriteCalls = newCounterVec(namespace, "write_calls_total", "Number of calls to Write.")
	ReadCalls = newCounterVec(namespace, "read_calls_total", "Number of calls to Read.")
	WriteEntries = newCounterVec(namespace, "write_entries_total",
		"Number of written entries.")
	ReadEntries = newCounterVec(namespace, "read_entries_total",
		"Number of read entries.")
}

func newCounterVec(namespace, name, help string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "ringbuf",
			Name:      name,
			Help:      help,
		},
		[]string{"id", "desc"},
	)
}
