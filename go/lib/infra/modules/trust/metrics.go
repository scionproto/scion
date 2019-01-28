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

package trust

import (
	"sync"

	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	promNamespace = "trust"
)

var (
	chainPushMetrics *infra.HandlerMetrics
	chainReqMetrics  *infra.HandlerMetrics
	trcPushMetrics   *infra.HandlerMetrics
	trcReqMetrics    *infra.HandlerMetrics

	initOnce sync.Once
)

func initMetrics() {
	initOnce.Do(func() {
		chainPushMetrics = &infra.HandlerMetrics{
			RequestsTotal: prom.NewCounterVec(promNamespace, "", "chain_push_total",
				"Chain pushes received total.", []string{}),
			RequestLatency: prom.NewHistogramVec(promNamespace, "", "chain_push_latency",
				"Chain push latency.", []string{prom.LabelStatus}, prom.DefaultLatencyBuckets),
			ResultsTotal: prom.NewCounterVec(promNamespace, "", "chain_push_results_total",
				"Chain push results total.", []string{prom.LabelResult}),
		}
		chainReqMetrics = &infra.HandlerMetrics{
			RequestsTotal: prom.NewCounterVec(promNamespace, "", "chain_req_total",
				"Chain requests received total.", []string{prom.LabelSrc}),
			RequestLatency: prom.NewHistogramVec(promNamespace, "", "chain_req_latency",
				"Chain requests latency.", []string{prom.LabelStatus}, prom.DefaultLatencyBuckets),
			ResultsTotal: prom.NewCounterVec(promNamespace, "", "chain_req_results_total",
				"Chain requests results total.", []string{prom.LabelResult}),
		}
		trcPushMetrics = &infra.HandlerMetrics{
			RequestsTotal: prom.NewCounterVec(promNamespace, "", "trc_push_total",
				"TRC pushes received total.", []string{}),
			RequestLatency: prom.NewHistogramVec(promNamespace, "", "trc_push_latency",
				"TRC push latency.", []string{prom.LabelStatus}, prom.DefaultLatencyBuckets),
			ResultsTotal: prom.NewCounterVec(promNamespace, "", "trc_push_results_total",
				"TRC push results total.", []string{prom.LabelResult}),
		}
		trcReqMetrics = &infra.HandlerMetrics{
			RequestsTotal: prom.NewCounterVec(promNamespace, "", "trc_req_total",
				"TRC requests received total.", []string{prom.LabelSrc}),
			RequestLatency: prom.NewHistogramVec(promNamespace, "", "trc_req_latency",
				"TRC requests latency.", []string{prom.LabelStatus}, prom.DefaultLatencyBuckets),
			ResultsTotal: prom.NewCounterVec(promNamespace, "", "trc_req_results_total",
				"TRC requests results total.", []string{prom.LabelResult}),
		}
	})
}
