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

package sring

import (
	"github.com/prometheus/client_golang/prometheus"
)

type sringMetrics struct {
	resvCalls    prometheus.Counter
	relCalls     prometheus.Counter
	writeCalls   prometheus.Counter
	readCalls    prometheus.Counter
	resvEntries  prometheus.Counter
	relEntries   prometheus.Counter
	writeEntries prometheus.Counter
	readEntries  prometheus.Counter
}

func newSRingMetrics(desc string, labels prometheus.Labels) *sringMetrics {
	l := copyLabels(labels)
	l["desc"] = desc
	return &sringMetrics{
		resvCalls:    ReserveCalls.With(l),
		relCalls:     ReleaseCalls.With(l),
		writeCalls:   WriteCalls.With(l),
		readCalls:    ReadCalls.With(l),
		resvEntries:  ReserveEntries.With(l),
		relEntries:   ReleaseEntries.With(l),
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

var ReserveCalls *prometheus.CounterVec
var ReleaseCalls *prometheus.CounterVec
var WriteCalls *prometheus.CounterVec
var ReadCalls *prometheus.CounterVec

var ReserveEntries *prometheus.CounterVec
var ReleaseEntries *prometheus.CounterVec
var WriteEntries *prometheus.CounterVec
var ReadEntries *prometheus.CounterVec

func InitMetrics(namespace string) {
	ReserveCalls = newCounterVec(namespace, "reserve_calls_total", "Number of calls to Reserve.")
	ReleaseCalls = newCounterVec(namespace, "release_calls_total", "Number of calls to Release.")
	WriteCalls = newCounterVec(namespace, "write_calls_total", "Number of calls to Write.")
	ReadCalls = newCounterVec(namespace, "read_calls_total", "Number of calls to Read.")

	ReserveEntries = newCounterVec(namespace, "reserve_entries_total",
		"Number of reserved entries.")
	ReleaseEntries = newCounterVec(namespace, "release_entries_total",
		"Number of released entries.")
	WriteEntries = newCounterVec(namespace, "write_entries_total",
		"Number of written entries.")
	ReadEntries = newCounterVec(namespace, "read_entries_total",
		"Number of read entries.")
}

func newCounterVec(namespace, name, help string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      name,
			Help:      help,
		},
		[]string{"id", "desc"},
	)
}
