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

package conn

import (
	"github.com/prometheus/client_golang/prometheus"
)

var RecvOverflow *prometheus.CounterVec
var RecvDelay *prometheus.CounterVec

func InitMetrics(namespace string) {
	RecvOverflow = newCounterVec(namespace, "recv_ovfl_count",
		"Number of packets dropped due to kernel receive buffer overflow.")
	RecvDelay = newCounterVec(namespace, "recv_delay_seconds",
		"How long packets spend in the kernel receive buffer.")
}

func newCounterVec(namespace, name, help string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "over_conn",
			Name:      name,
			Help:      help,
		},
		[]string{"id"},
	)
}

type metrics struct {
	recvOvfl  prometheus.Counter
	recvDelay prometheus.Counter
}

func newMetrics(labels prometheus.Labels) *metrics {
	return &metrics{
		recvOvfl:  RecvOverflow.With(labels),
		recvDelay: RecvDelay.With(labels),
	}
}
