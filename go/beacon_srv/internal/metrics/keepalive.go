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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

// KeepaliveLabels is used by clients to pass in a safe way labels
// to prometheus metric types (e.g. counter)
type KeepaliveLabels struct {
	IfID   common.IFIDType
	Result string
}

func (l KeepaliveLabels) labels() []string {
	return []string{"ifid", prom.LabelResult}
}

func (l *KeepaliveLabels) values() []string {
	return []string{l.IfID.String(), l.Result}
}

type exporter struct {
	out, in prometheus.CounterVec
}

func newKeepalive() exporter {
	sub := "keepalive"
	labels := KeepaliveLabels{}.labels()

	return exporter{
		out: *prom.NewCounterVec(namespace, sub, "transmit_msgs_total",
			"Total number of transmitted keepalive msgs.", labels),
		in: *prom.NewCounterVec(namespace, sub, "receive_msgs_total",
			"Total number of received keepalive msgs.", labels),
	}

}

// Transmits returns transmit counter
func (e *exporter) Transmits(l KeepaliveLabels) prometheus.Counter {
	return e.out.WithLabelValues(l.values()...)
}

// Receives returns the receive counter
func (e *exporter) Receives(l KeepaliveLabels) prometheus.Counter {
	return e.in.WithLabelValues(l.values()...)
}
