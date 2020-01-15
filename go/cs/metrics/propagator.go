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

// PropagatorLabels define the labels attached to propagator metrics.
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

type propagator struct {
	propagatedBeacons, intfTime *prometheus.CounterVec
	runtime, internalErrors     prometheus.Counter
}

func newPropagator() propagator {
	ns, sub := BSNamespace, "beaconing"
	return propagator{
		propagatedBeacons: prom.NewCounterVecWithLabels(ns, sub,
			"propagated_beacons_total",
			"Number of beacons propagated", PropagatorLabels{}),
		intfTime: prom.NewCounterVecWithLabels(ns, sub,
			"propagator_interface_duration_seconds_total",
			"Propagator total time spent per egress interface", PropagatorLabels{}),
		runtime: prom.NewCounter(ns, sub, "propagator_run_duration_seconds_total",
			"Propagator total run time spent on every periodic run"),
		internalErrors: prom.NewCounter(ns, sub, "propagator_errors_total",
			"Propagator total internal errors"),
	}
}

func (e *propagator) Runtime() prometheus.Counter {
	return e.runtime
}

func (e *propagator) Beacons(l PropagatorLabels) prometheus.Counter {
	return e.propagatedBeacons.WithLabelValues(l.Values()...)
}

func (e *propagator) IntfTime(l PropagatorLabels) prometheus.Counter {
	return e.intfTime.WithLabelValues(l.Values()...)
}

func (e *propagator) InternalErrors() prometheus.Counter {
	return e.internalErrors
}
