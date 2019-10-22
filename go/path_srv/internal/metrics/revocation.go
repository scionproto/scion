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

	"github.com/scionproto/scion/go/lib/prom"
)

// RevocationLabels are the labels for revocation metrics.
type RevocationLabels struct {
	Result string
	Src    string
}

// Labels returns the labels.
func (l RevocationLabels) Labels() []string {
	return []string{prom.LabelResult, prom.LabelSrc}
}

// Values returns the values for the labels.
func (l RevocationLabels) Values() []string {
	return []string{l.Result, l.Src}
}

// WithResult returns the labels with the result set.
func (l RevocationLabels) WithResult(result string) RevocationLabels {
	l.Result = result
	return l
}

type revocation struct {
	count *prometheus.CounterVec
}

func newRevocation() revocation {
	return revocation{
		count: prom.NewCounterVecWithLabels(Namespace, "revocations", "received_total",
			"The amount of revocations received by src type and result",
			RevocationLabels{}),
	}
}

func (r revocation) Count(l RevocationLabels) prometheus.Counter {
	return r.count.WithLabelValues(l.Values()...)
}
