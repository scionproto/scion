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
	"context"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
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

	allOps = []promOp{
		promOpSendAck,
		promOpGetTRC,
		promOpSendTRC,
		promOpGetCrtChain,
		promOpSendCrtChain,
		promOpSendIfId,
		promOpSendIfStateInfo,
		promOpSendSeg,
		promOpGetSegs,
		promOpSendSegReply,
		promOpSendSegSync,
		promOpGetSegChangesId,
		promOpSendSegChangesIdReply,
		promOpGetSegChanges,
		promOpSendSegChanges,
		promOpRequestChainIssue,
		promOpSendChainIssue,
	}

	allResults = []string{
		prom.ResultOk,
		prom.ErrTimeout,
		prom.ErrNotClassified,
	}

	initMetricsOnce sync.Once
)

func initMetrics() {
	// TODO(lukedirtwalker): add latency metric
	initMetricsOnce.Do(func() {
		// Cardinality: 17 (len(allOps))
		callsTotal = prom.NewCounterVec(promNamespace, "", "calls_total",
			"Total calls on the messenger.", []string{prom.LabelOperation})
		// Cardinality: X (len(allResults) * 17 (len(allOps))
		resultsTotal = prom.NewCounterVec(promNamespace, "", "results_total",
			"The results of messenger calls", []string{prom.LabelResult, prom.LabelOperation})
		latency = prom.NewHistogramVec(promNamespace, "", "calls_latency",
			"Histogram of call latency in seconds.",
			[]string{prom.LabelResult, prom.LabelOperation},
			[]float64{0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0})
	})
}

// WithMetrics returns the given messenger with metrics.
func WithMetrics(msger infra.Messenger) infra.Messenger {
	initMetrics()
	return &metricsMsger{
		msger: msger,
		metrics: &metrics{
			opCounters: opCounters(),
			results:    resultCounters(),
		},
	}
}

func opCounters() map[promOp]prometheus.Counter {
	opCounters := make(map[promOp]prometheus.Counter)
	for _, op := range allOps {
		opCounters[op] = callsTotal.With(prometheus.Labels{
			prom.LabelOperation: string(op),
		})
	}
	return opCounters
}

func resultCounters() map[promOp]map[string]prometheus.Counter {
	results := make(map[promOp]map[string]prometheus.Counter)
	for _, op := range allOps {
		results[op] = make(map[string]prometheus.Counter)
		for _, res := range allResults {
			results[op][res] = resultsTotal.With(prometheus.Labels{
				prom.LabelOperation: string(op),
				prom.LabelResult:    res,
			})
		}
	}
	return results
}

type metrics struct {
	opCounters map[promOp]prometheus.Counter
	results    map[promOp]map[string]prometheus.Counter
}

func (m *metrics) startOp(op promOp) opMetrics {
	m.opCounters[op].Inc()
	return opMetrics{
		op:        op,
		resultMap: m.results[op],
		begin:     time.Now(),
	}
}

type opMetrics struct {
	op        promOp
	resultMap map[string]prometheus.Counter
	begin     time.Time
}

func (m *opMetrics) observeResult(err error) {
	resLabel := errorToResultLabel(err)
	latency.With(prometheus.Labels{
		prom.LabelOperation: string(m.op),
		prom.LabelResult:    resLabel,
	}).Observe(time.Since(m.begin).Seconds())
	m.resultMap[resLabel].Inc()
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

var _ infra.Messenger = (*metricsMsger)(nil)

type metricsMsger struct {
	msger   infra.Messenger
	metrics *metrics
}

func (m *metricsMsger) SendAck(ctx context.Context, msg *ack.Ack, a net.Addr, id uint64) error {
	om := m.metrics.startOp(promOpSendAck)
	err := m.msger.SendAck(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq,
	a net.Addr, id uint64) (*cert_mgmt.TRC, error) {

	om := m.metrics.startOp(promOpGetTRC)
	trc, err := m.msger.GetTRC(ctx, msg, a, id)
	om.observeResult(err)
	return trc, err
}

func (m *metricsMsger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendTRC)
	err := m.msger.SendTRC(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr, id uint64) (*cert_mgmt.Chain, error) {

	om := m.metrics.startOp(promOpGetCrtChain)
	chain, err := m.msger.GetCertChain(ctx, msg, a, id)
	om.observeResult(err)
	return chain, err
}

func (m *metricsMsger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendCrtChain)
	err := m.msger.SendCertChain(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) SendIfId(ctx context.Context, msg *ifid.IFID,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendIfId)
	err := m.msger.SendIfId(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) SendIfStateInfos(ctx context.Context, msg *path_mgmt.IFStateInfos,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendIfStateInfo)
	err := m.msger.SendIfStateInfos(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) SendSeg(ctx context.Context, msg *seg.PathSegment,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendSeg)
	err := m.msger.SendSeg(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) GetSegs(ctx context.Context, msg *path_mgmt.SegReq,
	a net.Addr, id uint64) (*path_mgmt.SegReply, error) {

	om := m.metrics.startOp(promOpGetSegs)
	reply, err := m.msger.GetSegs(ctx, msg, a, id)
	om.observeResult(err)
	return reply, err
}

func (m *metricsMsger) SendSegReply(ctx context.Context, msg *path_mgmt.SegReply,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendSegReply)
	err := m.msger.SendSegReply(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) SendSegSync(ctx context.Context, msg *path_mgmt.SegSync,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendSegSync)
	err := m.msger.SendSegSync(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) GetSegChangesIds(ctx context.Context, msg *path_mgmt.SegChangesIdReq,
	a net.Addr, id uint64) (*path_mgmt.SegChangesIdReply, error) {

	om := m.metrics.startOp(promOpGetSegChangesId)
	reply, err := m.msger.GetSegChangesIds(ctx, msg, a, id)
	om.observeResult(err)
	return reply, err
}

func (m *metricsMsger) SendSegChangesIdReply(ctx context.Context, msg *path_mgmt.SegChangesIdReply,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendSegChangesIdReply)
	err := m.msger.SendSegChangesIdReply(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) GetSegChanges(ctx context.Context, msg *path_mgmt.SegChangesReq,
	a net.Addr, id uint64) (*path_mgmt.SegChangesReply, error) {

	om := m.metrics.startOp(promOpGetSegChanges)
	reply, err := m.msger.GetSegChanges(ctx, msg, a, id)
	om.observeResult(err)
	return reply, err
}

func (m *metricsMsger) SendSegChangesReply(ctx context.Context, msg *path_mgmt.SegChangesReply,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendSegChanges)
	err := m.msger.SendSegChangesReply(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) RequestChainIssue(ctx context.Context, msg *cert_mgmt.ChainIssReq,
	a net.Addr, id uint64) (*cert_mgmt.ChainIssRep, error) {

	om := m.metrics.startOp(promOpRequestChainIssue)
	reply, err := m.msger.RequestChainIssue(ctx, msg, a, id)
	om.observeResult(err)
	return reply, err
}

func (m *metricsMsger) SendChainIssueReply(ctx context.Context, msg *cert_mgmt.ChainIssRep,
	a net.Addr, id uint64) error {

	om := m.metrics.startOp(promOpSendChainIssue)
	err := m.msger.SendChainIssueReply(ctx, msg, a, id)
	om.observeResult(err)
	return err
}

func (m *metricsMsger) UpdateSigner(signer ctrl.Signer, types []infra.MessageType) {
	m.msger.UpdateSigner(signer, types)
}

func (m *metricsMsger) UpdateVerifier(verifier ctrl.SigVerifier) {
	m.msger.UpdateVerifier(verifier)
}

func (m *metricsMsger) AddHandler(msgType infra.MessageType, h infra.Handler) {
	m.msger.AddHandler(msgType, h)
}

func (m *metricsMsger) ListenAndServe() {
	m.msger.ListenAndServe()
}

func (m *metricsMsger) CloseServer() error {
	return m.msger.CloseServer()
}
