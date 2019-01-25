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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	promNamespace = "messenger"
)

type promOp string

const (
	promOpSendAck               promOp = "send_ack"
	promOpGetTRC                promOp = "get_trc"
	promOpSendTRC               promOp = "send_trc"
	promOpGetCrtChain           promOp = "get_chain"
	promOpSendCrtChain          promOp = "send_crt_chain"
	promOpSendIfId              promOp = "send_ifid"
	promOpSendIfStateInfo       promOp = "send_if_info"
	promOpSendSeg               promOp = "send_seg"
	promOpGetSegs               promOp = "get_segs"
	promOpSendSegReply          promOp = "send_seg_reply"
	promOpSendSegSync           promOp = "send_seg_sync"
	promOpGetSegChangesId       promOp = "get_seg_changes_id"
	promOpSendSegChangesIdReply promOp = "send_seg_change_reply"
	promOpGetSegChanges         promOp = "get_seg_changes"
	promOpSendSegChanges        promOp = "send_seg_changes"
	promOpRequestChainIssue     promOp = "request_chain_issue"
	promOpSendChainIssue        promOp = "send_chain_issue_reply"
)

var (
	callsTotal   *prometheus.CounterVec
	resultsTotal *prometheus.CounterVec
	latency      *prometheus.HistogramVec
)

func init() {
	// Cardinality: 17 (len(allOps))
	callsTotal = prom.NewCounterVec(promNamespace, "", "calls_total",
		"Total calls on the messenger.", []string{prom.LabelOperation})
	// Cardinality: X (len(allResults) * 17 (len(allOps))
	resultsTotal = prom.NewCounterVec(promNamespace, "", "results_total",
		"The results of messenger calls", []string{prom.LabelResult, prom.LabelOperation})
	latency = prom.NewHistogramVec(promNamespace, "", "calls_latency",
		"Histogram of call latency in seconds.", []string{prom.LabelResult, prom.LabelOperation},
		[]float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24})
}

func metricStartOp(op promOp) opMetrics {
	callsTotal.With(prometheus.Labels{
		prom.LabelOperation: string(op),
	}).Inc()
	return opMetrics{
		op:    op,
		begin: time.Now(),
	}
}

type opMetrics struct {
	op    promOp
	begin time.Time
}

func (m *opMetrics) publishResult(err error) {
	resLabel := errorToResultLabel(err)
	resLabels := prometheus.Labels{
		prom.LabelOperation: string(m.op),
		prom.LabelResult:    resLabel,
	}
	latency.With(resLabels).Observe(time.Since(m.begin).Seconds())
	resultsTotal.With(resLabels).Inc()
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
