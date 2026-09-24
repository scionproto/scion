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

package segfetcher

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/segment/seghandler"
)

// Metrics contains the metrics for the segfetcher.
type Metrics struct {
	// Requests counts the number of requests by result.
	Requests func(result error) metrics.Counter
	// Revocations counts the number of revocations by result and source.
	Revocations func(result error, src string) metrics.Counter
}

// NewMetrics exposes the metrics constructor.
func NewMetrics(opts ...metrics.Option) Metrics {
	auto := metrics.ApplyOptions(opts...).Auto()
	requests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "segfetcher_requests_total",
		Help: "The number of segment requests sent.",
	}, []string{prom.LabelResult})
	revocations := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "segfetcher_received_revocations_total",
		Help: "The number of revocations received.",
	}, []string{prom.LabelResult, prom.LabelSrc})
	return Metrics{
		Requests: func(result error) metrics.Counter {
			return requests.With(prometheus.Labels{prom.LabelResult: ErrToMetricsLabel(result)})
		},
		Revocations: func(result error, src string) metrics.Counter {
			return revocations.With(prometheus.Labels{
				prom.LabelResult: ErrToMetricsLabel(result),
				prom.LabelSrc:    src,
			})
		},
	}
}

// ErrToMetricsLabel classifies the error from the segfetcher into metrics
// labels.
func ErrToMetricsLabel(err error) string {
	switch {
	case serrors.IsTimeout(err):
		return prom.ErrTimeout
	case errors.Is(err, errDB), errors.Is(err, seghandler.ErrDB):
		return prom.ErrDB
	case errors.Is(err, errFetch):
		return prom.ErrNetwork
	case errors.Is(err, seghandler.ErrVerification):
		return prom.ErrVerify
	default:
		return prom.ErrNotClassified
	}
}
