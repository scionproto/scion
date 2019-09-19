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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

// RevocationLabels define the labels attached to revocation metrics.
type RevocationLabels struct {
	IfID   common.IFIDType
	Result string
	Dst    string
}

// Labels returns the list of labels.
func (l RevocationLabels) Labels() []string {
	return []string{"if_id", prom.LabelResult, "dst"}
}

// Values returns the label values in the order defined by Labels.
func (l RevocationLabels) Values() []string {
	return []string{l.IfID.String(), l.Result, l.Dst}
}

type exporterR struct {
	out, in, store prometheus.CounterVec
}

func newRevocation() exporterR {
	sub := "revocation"
	labels := RevocationLabels{}.Labels()

	return exporterR{
		out: *prom.NewCounterVec(Namespace, sub, "transmit_rev_total",
			"Total number of transmitted revocation msgs.", labels),
		in: *prom.NewCounterVec(Namespace, sub, "receive_rev_total",
			"Total number of received revocation msgs.", labels),
		store: *prom.NewCounterVec(Namespace, sub, "store_rev_total",
			"Total number of stored revocation.", labels),
	}

}

// Transmits returns transmit counter.
func (e *exporterR) Transmits(l RevocationLabels) prometheus.Counter {
	return e.out.WithLabelValues(l.Values()...)
}

// Receives returns receive counter.
func (e *exporterR) Receives(l RevocationLabels) prometheus.Counter {
	return e.in.WithLabelValues(l.Values()...)
}

// Receives returns store counter.
func (e *exporterR) Stores(l RevocationLabels) prometheus.Counter {
	return e.store.WithLabelValues(l.Values()...)
}
