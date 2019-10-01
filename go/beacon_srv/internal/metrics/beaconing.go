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
	NeighAS addr.IA
	Result  string
}

// Labels returns the name of the labels in correct order.
func (l BeaconingLabels) Labels() []string {
	return []string{"in_if_id", "neigh_as", prom.LabelResult}
}

// Values returns the values of the label in correct order.
func (l BeaconingLabels) Values() []string {
	return []string{l.InIfID.String(), l.NeighAS.String(), l.Result}
}

// WithResult return the label set with the modfied result.
func (l BeaconingLabels) WithResult(result string) BeaconingLabels {
	l.Result = result
	return l
}

// PropagatorLabels is used by clients to pass in a safe way labels
// values to prometheus metric types (e.g. counter).
type PropagatorLabels struct {
	InIfID, EgIfID common.IFIDType
	StartIA        addr.IA
	Result         string
}

// Labels returns the name of the labels in correct order.
func (l PropagatorLabels) Labels() []string {
	return []string{"start_ia", "in_if_id", "eg_if_id", prom.LabelResult}
}

// Values returns the values of the label in correct order.
func (l PropagatorLabels) Values() []string {
	return []string{l.StartIA.String(), l.InIfID.String(), l.EgIfID.String(), l.Result}
}

type beaconing struct {
	in                  prometheus.CounterVec
	proTotalBeacons     prometheus.CounterVec
	proTotalIntfTime    prometheus.CounterVec
	proTotalRunTime     prometheus.Counter
	proTotalInternalErr prometheus.Counter
}

func newBeaconing() beaconing {
	ns, sub := Namespace, "beaconing"

	return beaconing{
		in: *prom.NewCounterVec(ns, sub, "received_beacons_total",
			"Total number of received beacons.", BeaconingLabels{}.Labels()),
		proTotalBeacons: *prom.NewCounterVec(ns, sub, "propagated_beacons_total",
			"Number of beacons propagated", PropagatorLabels{}.Labels()),
		proTotalIntfTime: *prom.NewCounterVec(ns, sub,
			"propagator_interface_duration_seconds_total",
			"Propagator total time spent per egress interface", PropagatorLabels{}.Labels()),
		proTotalRunTime: prom.NewCounter(ns, sub, "propagator_run_duration_seconds_total",
			"Propagator total run time spent on every periodic run"),
		proTotalInternalErr: prom.NewCounter(ns, sub, "propagator_errors_total",
			"Propagator total internal errors"),
	}
}

func (e *beaconing) Received(l BeaconingLabels) prometheus.Counter {
	return e.in.WithLabelValues(l.Values()...)
}

func (e *beaconing) PropagatorTotalRunTime() prometheus.Counter {
	return e.proTotalRunTime
}

func (e *beaconing) PropagatorTotalBeacons(l PropagatorLabels) prometheus.Counter {
	return e.proTotalBeacons.WithLabelValues(l.Values()...)
}

func (e *beaconing) PropagatorIntfTime(l PropagatorLabels) prometheus.Counter {
	return e.proTotalIntfTime.WithLabelValues(l.Values()...)
}

func (e *beaconing) PropagatorInternalErr() prometheus.Counter {
	return e.proTotalInternalErr
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
