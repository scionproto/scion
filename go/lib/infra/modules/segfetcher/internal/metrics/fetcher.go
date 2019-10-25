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

const revSrcPathReply = "path_reply"

// RequestLabels contains the labels for the request metrics.
type RequestLabels struct {
	Result string
}

// Labels returns the labels.
func (l RequestLabels) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the values.
func (l RequestLabels) Values() []string {
	return []string{l.Result}
}

// WithResult returns a copy of l with the result changed.
func (l RequestLabels) WithResult(result string) RequestLabels {
	l.Result = result
	return l
}

// RevocationLabels are the labels for revocation metrics.
type RevocationLabels struct {
	Result string
	Src    string
}

// Labels returns the labels.
func (l RevocationLabels) Labels() []string {
	return []string{prom.LabelResult, prom.LabelSrc}
}

// Values returns the values.
func (l RevocationLabels) Values() []string {
	return []string{l.Result, l.Src}
}

// WithResult returns a copy of l with the result changed.
func (l RevocationLabels) WithResult(result string) RevocationLabels {
	l.Result = result
	return l
}

// Fetcher exposes all metrics for the fetcher.
type Fetcher interface {
	SegRequests(labels RequestLabels) prometheus.Counter
	RevocationsReceived(labels RevocationLabels) prometheus.Counter
	UpdateRevocation(stored int, dbErrs int, verifyErrs int)
}

type fetcher struct {
	segRequest  *prometheus.CounterVec
	revocations *prometheus.CounterVec
}

// NewFetcher creates fetcher metrics struct.
func NewFetcher(namespace string) Fetcher {
	sub := "fetcher"
	return fetcher{
		segRequest: prom.NewCounterVecWithLabels(namespace, sub, "seg_requests_total",
			"The number of segment request sent.", RequestLabels{Result: OkSuccess}),
		revocations: prom.NewCounterVecWithLabels(namespace, "", "received_revocations_total",
			"The amount of revocations received.",
			RevocationLabels{Result: OkSuccess, Src: revSrcPathReply}),
	}
}

func (f fetcher) SegRequests(l RequestLabels) prometheus.Counter {
	return f.segRequest.WithLabelValues(l.Values()...)
}

func (f fetcher) RevocationsReceived(l RevocationLabels) prometheus.Counter {
	l.Src = revSrcPathReply
	return f.revocations.WithLabelValues(l.Values()...)
}

func (f fetcher) UpdateRevocation(stored int, dbErrs int, verifyErrs int) {
	f.RevocationsReceived(RevocationLabels{Result: OkSuccess}).Add(float64(stored))
	f.RevocationsReceived(RevocationLabels{Result: ErrDB}).Add(float64(dbErrs))
	f.RevocationsReceived(RevocationLabels{Result: ErrVerify}).Add(float64(verifyErrs))
}
