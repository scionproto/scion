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
	caActive        prometheus.Gauge
	caSigners       prometheus.CounterVec
	signedChains    prometheus.CounterVec
	lastGeneratedCA prometheus.Gauge
	expirationCA    prometheus.Gauge
}

func newSigner() signer {
	return signer{
		caActive: prom.NewGauge(Namespace, "",
			"signer_active_boolean",
			"Whether the CA signer is active and can sign certificate chains",
		),
		caSigners: *prom.NewCounterVecWithLabels(Namespace, "",
			"generated_signers_total",
			"Number of generated CA signers that sign certificate chains",
			SignerLabels{},
		),
		signedChains: *prom.NewCounterVecWithLabels(Namespace, "",
			"signed_certificate_chains_total",
			"Number of certificate chains signed",
			SignerLabels{},
		),
		lastGeneratedCA: prom.NewGauge(Namespace, "",
			"last_signer_generation_time_second",
			"The last time a signer for creating AS certificates was successfully generated",
		),
		expirationCA: prom.NewGauge(Namespace, "",
			"signer_expiration_time_second",
			"The expiration time of the current CA signer",
		),
	}
}

func (s *signer) ActiveCA() prometheus.Gauge {
	return s.caActive
}

func (s *signer) SignedChains(l SignerLabels) prometheus.Counter {
	return s.signedChains.WithLabelValues(l.Values()...)
}

func (s *signer) GenerateCA(l SignerLabels) prometheus.Counter {
	return s.caSigners.WithLabelValues(l.Values()...)
}

func (s *signer) LastGeneratedCA() prometheus.Gauge {
	return s.lastGeneratedCA
}

func (s *signer) ExpirationCA() prometheus.Gauge {
	return s.expirationCA
}

// Timestamp return the prometheus value for gauge.
func Timestamp(ts time.Time) float64 {
	if ts.IsZero() {
		return 0
	}
	return float64(ts.UnixNano() / 1e9)
}
