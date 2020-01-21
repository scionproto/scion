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

// VerifierLabels defines the trust material resolver labels.
type VerifierLabels struct {
	Result string
}

// Labels returns the list of labels.
func (l VerifierLabels) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l VerifierLabels) Values() []string {
	return []string{l.Result}
}

// WithResult returns the lookup labels with the modified result.
func (l VerifierLabels) WithResult(result string) VerifierLabels {
	l.Result = result
	return l
}

type verifier struct {
	signatures prometheus.CounterVec
}

func newVerifier() verifier {
	return verifier{
		signatures: *prom.NewCounterVecWithLabels(Namespace, "", "verified_signatures_total",
			"Number of signatures verifications backed by the trust store", VerifierLabels{}),
	}
}

func (s *verifier) Verify(l VerifierLabels) prometheus.Counter {
	return s.signatures.WithLabelValues(l.Values()...)
}
