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

// ProviderLabels defines the trust material provider labels.
type ProviderLabels struct {
	Type    string
	Trigger string
	Result  string
}

// Labels returns the list of labels.
func (l ProviderLabels) Labels() []string {
	return []string{"type", "trigger", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l ProviderLabels) Values() []string {
	return []string{l.Type, l.Trigger, l.Result}
}

// WithResult returns the lookup labels with the modified result.
func (l ProviderLabels) WithResult(result string) ProviderLabels {
	l.Result = result
	return l
}

type provider struct {
	requests prometheus.CounterVec
}

func newProvider() provider {
	return provider{
		requests: *prom.NewCounterVecWithLabels(Namespace, "", "lookups_total",
			"Number of trust material lookups handled by the trust store", ProviderLabels{}),
	}
}

func (p *provider) Request(l ProviderLabels) prometheus.Counter {
	return p.requests.WithLabelValues(l.Values()...)
}
