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

// RegistrarLabels define the labels attached to registrar metrics.
type RegistrarLabels struct {
	InIfID          common.IFIDType
	StartIA         addr.IA
	Result, SegType string
}

// Labels returns the name of the labels in correct order.
func (l RegistrarLabels) Labels() []string {
	return []string{"start_ia", "in_if_id", "seg_type", prom.LabelResult}
}

// Values returns the values of the label in correct order.
func (l RegistrarLabels) Values() []string {
	return []string{l.StartIA.String(), l.InIfID.String(), l.SegType, l.Result}
}

// TypeOnlyLabel is used by clients to pass in a safe way labels
// values to prometheus metric types (e.g. counter).
type TypeOnlyLabel struct {
	SegType string
}

// Labels returns the name of the labels in correct order.
func (l TypeOnlyLabel) Labels() []string {
	return []string{"seg_type"}
}

// Values returns the values of the label in correct order.
func (l TypeOnlyLabel) Values() []string {
	return []string{l.SegType}
}

type registrar struct {
	registeredBeacons, runtime, internalErrors *prometheus.CounterVec
}

func newRegistrar() registrar {
	ns, sub := BSNamespace, "beaconing"
	return registrar{
		registeredBeacons: prom.NewCounterVecWithLabels(ns, sub, "registered_beacons_total",
			"Number of beacons registered",
			RegistrarLabels{}),
		runtime: prom.NewCounterVecWithLabels(ns, sub, "registrar_run_durations_seconds_total",
			"Registrar total time spent on every periodic run", TypeOnlyLabel{"up"}),
		internalErrors: prom.NewCounterVecWithLabels(ns, sub, "registrar_errors_total",
			"Registrar total internal errors", TypeOnlyLabel{"up"}),
	}
}

func (e *registrar) Beacons(l RegistrarLabels) prometheus.Counter {
	return e.registeredBeacons.WithLabelValues(l.Values()...)
}

func (e *registrar) RuntimeWithType(s string) prometheus.Counter {
	l := TypeOnlyLabel{SegType: s}
	return e.runtime.WithLabelValues(l.Values()...)
}

func (e *registrar) InternalErrorsWithType(s string) prometheus.Counter {
	l := TypeOnlyLabel{SegType: s}
	return e.internalErrors.WithLabelValues(l.Values()...)
}
