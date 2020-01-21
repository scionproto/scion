// Copyright 2020 Anapaya Systems
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

	"github.com/scionproto/scion/go/lib/prom"
)

// InserterLabels defines the trust material insert labels.
type InserterLabels struct {
	Type   string
	Result string
}

// Labels returns the list of labels.
func (l InserterLabels) Labels() []string {
	return []string{"type", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l InserterLabels) Values() []string {
	return []string{l.Type, l.Result}
}

// WithResult returns the lookup labels with the modified result.
func (l InserterLabels) WithResult(result string) InserterLabels {
	l.Result = result
	return l
}

type inserter struct {
	requests prometheus.CounterVec
}

func newInserter() inserter {
	return inserter{
		requests: *prom.NewCounterVecWithLabels(Namespace, "", "insertions_total",
			"Number of trust material insertions handled by the trust store", InserterLabels{}),
	}
}

func (i *inserter) Request(l InserterLabels) prometheus.Counter {
	return i.requests.WithLabelValues(l.Values()...)
}
