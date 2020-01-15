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

// OriginatorLabels define the labels attached to originator metrics.
type OriginatorLabels struct {
	EgIfID common.IFIDType
	Result string
}

// Labels returns the name of the labels in correct order.
func (l OriginatorLabels) Labels() []string {
	return []string{"eg_if_id", prom.LabelResult}
}

// Values returns the values of the label in correct order.
func (l OriginatorLabels) Values() []string {
	return []string{l.EgIfID.String(), l.Result}
}

// WithResult returns the label set with the modfied result.
func (l OriginatorLabels) WithResult(result string) OriginatorLabels {
	l.Result = result
	return l
}

type originator struct {
	originatedBeacons *prometheus.CounterVec
	runtime           prometheus.Counter
}

func newOriginator() originator {
	ns, sub := BSNamespace, "beaconing"
	return originator{
		originatedBeacons: prom.NewCounterVecWithLabels(ns, sub, "originated_beacons_total",
			"Number of beacons originated", OriginatorLabels{}),
		runtime: prom.NewCounter(ns, sub, "originator_run_duration_seconds_total",
			"Originator total time spent on every periodic run"),
	}
}

func (e *originator) Runtime() prometheus.Counter {
	return e.runtime
}

func (e *originator) Beacons(l OriginatorLabels) prometheus.Counter {
	return e.originatedBeacons.WithLabelValues(l.Values()...)
}
