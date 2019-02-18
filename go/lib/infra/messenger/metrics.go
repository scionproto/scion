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

package messenger

import (
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	promNamespace = "messenger"
)

var (
	outCallsTotal   *prometheus.CounterVec
	outResultsTotal *prometheus.CounterVec
	outCallsLatency *prometheus.HistogramVec

	inCallsTotal   *prometheus.CounterVec
	inResultsTotal *prometheus.CounterVec
	inCallsLatency *prometheus.HistogramVec

	initOnce sync.Once
)

func initMetrics() {
	initOnce.Do(func() {
		// Cardinality: 17 (len(allOps))
		outCallsTotal = prom.NewCounterVec(promNamespace, "", "out_calls_total",
			"Total out calls on the messenger.", []string{prom.LabelOperation})
		// Cardinality: X (len(allResults) * 17 (len(allOps))
		outResultsTotal = prom.NewCounterVec(promNamespace, "", "out_results_total",
			"The out results of messenger calls", []string{prom.LabelResult, prom.LabelOperation})
		outCallsLatency = prom.NewHistogramVec(promNamespace, "", "out_calls_latency",
			"Histogram of out call latency in seconds.",
			[]string{prom.LabelResult, prom.LabelOperation},
			prom.DefaultLatencyBuckets)

		inCallsTotal = prom.NewCounterVec(promNamespace, "", "in_calls_total",
			"Total in calls on the messenger.", []string{prom.LabelOperation, prom.LabelSrc})
		inResultsTotal = prom.NewCounterVec(promNamespace, "", "in_results_total",
			"The in results of messenger calls", []string{prom.LabelResult, prom.LabelOperation})
		inCallsLatency = prom.NewHistogramVec(promNamespace, "", "in_calls_latency",
			"Histogram of out call latency in seconds.",
			[]string{prom.LabelStatus, prom.LabelOperation},
			prom.DefaultLatencyBuckets)
	})
}

func metricSrcValue(peer net.Addr, localIA addr.IA) string {
	sAddr, ok := peer.(*snet.Addr)
	if !ok {
		return infra.PromSrcUnknown
	}
	if localIA.Equal(sAddr.IA) {
		return infra.PromSrcASLocal
	}
	if localIA.I == sAddr.IA.I {
		return infra.PromSrcISDLocal
	}
	return infra.PromSrcISDRemote
}

func metricStartOp(msgType infra.MessageType) opMetrics {
	outCallsTotal.With(prometheus.Labels{
		prom.LabelOperation: msgType.MetricLabel(),
	}).Inc()
	return opMetrics{
		mt:    msgType,
		begin: time.Now(),
	}
}

type opMetrics struct {
	mt    infra.MessageType
	begin time.Time
}

func (m *opMetrics) publishResult(err error) {
	resLabel := errorToResultLabel(err)
	resLabels := prometheus.Labels{
		prom.LabelOperation: m.mt.MetricLabel(),
		prom.LabelResult:    resLabel,
	}
	outCallsLatency.With(resLabels).Observe(time.Since(m.begin).Seconds())
	outResultsTotal.With(resLabels).Inc()
}

func errorToResultLabel(err error) string {
	// TODO(lukedirtwalker): categorize error better.
	switch {
	case err == nil:
		return prom.ResultOk
	case common.IsTimeoutErr(err):
		return prom.ErrTimeout
	default:
		return prom.ErrNotClassified
	}
}
