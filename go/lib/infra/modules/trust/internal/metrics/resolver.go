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

// ResolverLabels defines the trust material resolver labels.
type ResolverLabels struct {
	Type    string
	Trigger string
	Peer    string
	Result  string
}

// Labels returns the list of labels.
func (l ResolverLabels) Labels() []string {
	return []string{"type", "trigger", "peer", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l ResolverLabels) Values() []string {
	return []string{l.Type, l.Trigger, l.Peer, l.Result}
}

// WithResult returns the lookup labels with the modified result.
func (l ResolverLabels) WithResult(result string) ResolverLabels {
	l.Result = result
	return l
}

type resolver struct {
	fetches prometheus.CounterVec
}

func newResolver() resolver {
	return resolver{
		fetches: *prom.NewCounterVecWithLabels(Namespace, "", "sent_requests_total",
			"Number of trust material requests sent by the trust store", ResolverLabels{}),
	}
}

func (r *resolver) Fetch(l ResolverLabels) prometheus.Counter {
	return r.fetches.WithLabelValues(l.Values()...)
}
