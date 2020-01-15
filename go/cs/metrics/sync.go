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
	"github.com/scionproto/scion/go/lib/prom"
)

// SyncRegLabels contains the label values for synchronization registration metrics.
type SyncRegLabels struct {
	Result string
	Src    addr.IA
}

// Labels returns the labels.
func (l SyncRegLabels) Labels() []string {
	return []string{prom.LabelResult, prom.LabelSrc}
}

// Values returns the values.
func (l SyncRegLabels) Values() []string {
	return []string{l.Result, l.Src.String()}
}

// WithResult return the labels with a changed result.
func (l SyncRegLabels) WithResult(result string) SyncRegLabels {
	l.Result = result
	return l
}

// SyncPushLabels contains the label values for synchronization pushes.
type SyncPushLabels struct {
	Result string
	Dst    addr.IA
}

// Labels returns the labels.
func (l SyncPushLabels) Labels() []string {
	return []string{prom.LabelResult, "dst"}
}

// Values returns the values.
func (l SyncPushLabels) Values() []string {
	return []string{l.Result, l.Dst.String()}
}

// WithResult return the labels with a changed result.
func (l SyncPushLabels) WithResult(result string) SyncPushLabels {
	l.Result = result
	return l
}

type sync struct {
	registrations *prometheus.CounterVec
	pushes        *prometheus.CounterVec
}

func newSync() sync {
	subsystem := "segment_sync"
	return sync{
		registrations: prom.NewCounterVecWithLabels(PSNamespace, subsystem, "registrations_total",
			"Number of segments registered in down segment synchronizations",
			SyncRegLabels{}),
		pushes: prom.NewCounterVecWithLabels(PSNamespace, subsystem, "pushes_total",
			"Number of pushes towards a destination", SyncPushLabels{}),
	}
}

// Registrations returns the counter for synchronization registration messages.
func (s sync) Registrations(l SyncRegLabels) prometheus.Counter {
	return s.registrations.WithLabelValues(l.Values()...)
}

// RegistrationSuccess increments registrations with the given stats.
func (s sync) RegistrationSuccess(l SyncRegLabels, inserted, updated int) {
	s.Registrations(l.WithResult(OkRegistrationNew)).Add(float64(inserted))
	s.Registrations(l.WithResult(OkRegiststrationUpdated)).Add(float64(updated))
}

// Pushes returns the counter for synchronization pushes.
func (s sync) Pushes(l SyncPushLabels) prometheus.Counter {
	return s.pushes.WithLabelValues(l.Values()...)
}
