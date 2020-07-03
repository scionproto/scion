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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

// SignerLabels defines the trust material signer labels.
type SignerLabels struct {
	Result string
}

// Labels returns the list of labels.
func (l SignerLabels) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l SignerLabels) Values() []string {
	return []string{l.Result}
}

// WithResult returns the lookup labels with the modified result.
func (l SignerLabels) WithResult(result string) SignerLabels {
	l.Result = result
	return l
}

type signer struct {
	Signatures, Signers prometheus.CounterVec
	ASNotAfter          prometheus.Gauge
}

func newSigner() signer {
	return signer{
		Signatures: *prom.NewCounterVecWithLabels(Namespace, "", "created_signatures_total",
			"Number of signatures created with a signer backed by the trust engine",
			SignerLabels{}),
		Signers: *prom.NewCounterVecWithLabels(Namespace, "", "generated_signers_total",
			"Number of generated signers backed by the trust engine", SignerLabels{}),
	}
}

func (s *signer) Sign(l SignerLabels) prometheus.Counter {
	return s.Signatures.WithLabelValues(l.Values()...)
}

func (s *signer) Generate(l SignerLabels) prometheus.Counter {
	return s.Signers.WithLabelValues(l.Values()...)
}

// Timestamp return the prometheus value for gauge.
func Timestamp(ts time.Time) float64 {
	if ts.IsZero() {
		return 0
	}
	return float64(ts.UnixNano() / 1e9)
}
