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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

// BeaconingLabels is used by clients to pass in a safe way labels
// values to prometheus metric types (e.g. counter).
type BeaconingLabels struct {
	InIfID  common.IFIDType
	NeighIA addr.IA
	Result  string
}

// Labels returns the name of the labels in correct order.
func (l BeaconingLabels) Labels() []string {
	return []string{"in_if_id", prom.LabelNeighIA, prom.LabelResult}
}

// Values returns the values of the label in correct order.
func (l BeaconingLabels) Values() []string {
	return []string{l.InIfID.String(), l.NeighIA.String(), l.Result}
}

// WithResult returns the label set with the modfied result.
func (l BeaconingLabels) WithResult(result string) BeaconingLabels {
	l.Result = result
	return l
}

type beaconing struct {
	BeaconsReceived *prometheus.CounterVec
}

func newBeaconing() beaconing {
	ns, sub := BSNamespace, "beaconing"
	return beaconing{
		BeaconsReceived: prom.NewCounterVecWithLabels(ns, sub, "received_beacons_total",
			"Total number of received beacons.", BeaconingLabels{}),
	}
}

func (e *beaconing) Received(l BeaconingLabels) prometheus.Counter {
	return e.BeaconsReceived.WithLabelValues(l.Values()...)
}

// GetResultValue return result label value given insert stats.
func GetResultValue(ins, upd, flt int) string {
	switch {
	case flt > 0:
		return OkFiltered
	case upd > 0:
		return OkUpdated
	case ins > 0:
		return OkNew
	default:
		return OkOld
	}
}
