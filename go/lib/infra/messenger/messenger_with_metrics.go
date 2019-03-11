// Copyright 2019 ETH Zurich
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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/prom"
)

// MessengerWithMetrics exposes the API for sending and receiving CtrlPld
// messages, while also reporting metrics via Prometheus.
type MessengerWithMetrics struct {
	messenger infra.Messenger
	ia        addr.IA
}

// NewMessengerWithMetrics creates a Messenger that reports metrics via Prometheus.
func NewMessengerWithMetrics(config *Config) *MessengerWithMetrics {
	initMetrics()
	return &MessengerWithMetrics{
		messenger: New(config),
		ia:        config.IA,
	}
}

func (m *MessengerWithMetrics) SendAck(ctx context.Context, msg *ack.Ack, a net.Addr,
	id uint64) error {

	opMetric := metricStartOp(infra.Ack)
	err := m.messenger.SendAck(ctx, msg, a, id)
	opMetric.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq,
	a net.Addr, id uint64) (*cert_mgmt.TRC, error) {

	opMetric := metricStartOp(infra.TRCRequest)
	trc, err := m.messenger.GetTRC(ctx, msg, a, id)
	opMetric.publishResult(err)
	return trc, err
}

func (m *MessengerWithMetrics) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr,
	id uint64) error {

	opMetrics := metricStartOp(infra.TRC)
	err := m.messenger.SendTRC(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr, id uint64) (*cert_mgmt.Chain, error) {

	opMetrics := metricStartOp(infra.ChainRequest)
	chain, err := m.messenger.GetCertChain(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return chain, err
}

func (m *MessengerWithMetrics) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr,
	id uint64) error {

	opMetrics := metricStartOp(infra.Chain)
	err := m.messenger.SendCertChain(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) SendIfId(ctx context.Context, msg *ifid.IFID, a net.Addr,
	id uint64) error {

	opMetrics := metricStartOp(infra.IfId)
	err := m.messenger.SendIfId(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) SendIfStateInfos(ctx context.Context, msg *path_mgmt.IFStateInfos,
	a net.Addr, id uint64) error {

	opMetrics := metricStartOp(infra.IfStateInfos)
	err := m.messenger.SendIfStateInfos(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) SendSeg(ctx context.Context, msg *seg.PathSegment,
	a net.Addr, id uint64) error {

	opMetrics := metricStartOp(infra.Seg)
	err := m.messenger.SendSeg(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) GetSegs(ctx context.Context, msg *path_mgmt.SegReq,
	a net.Addr, id uint64) (*path_mgmt.SegReply, error) {

	opMetrics := metricStartOp(infra.SegRequest)
	reply, err := m.messenger.GetSegs(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return reply, err
}

func (m *MessengerWithMetrics) SendSegReply(ctx context.Context, msg *path_mgmt.SegReply,
	a net.Addr, id uint64) error {

	opMetrics := metricStartOp(infra.SegReply)
	err := m.messenger.SendSegReply(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) SendSegSync(ctx context.Context, msg *path_mgmt.SegSync,
	a net.Addr, id uint64) error {

	opMetrics := metricStartOp(infra.SegSync)
	err := m.messenger.SendSegSync(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) GetSegChangesIds(ctx context.Context, msg *path_mgmt.SegChangesIdReq,
	a net.Addr, id uint64) (*path_mgmt.SegChangesIdReply, error) {

	opMetrics := metricStartOp(infra.SegChangesIdReq)
	reply, err := m.messenger.GetSegChangesIds(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return reply, err
}

func (m *MessengerWithMetrics) SendSegChangesIdReply(ctx context.Context,
	msg *path_mgmt.SegChangesIdReply, a net.Addr, id uint64) error {

	opMetrics := metricStartOp(infra.SegChangesIdReply)
	err := m.messenger.SendSegChangesIdReply(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) GetSegChanges(ctx context.Context, msg *path_mgmt.SegChangesReq,
	a net.Addr, id uint64) (*path_mgmt.SegChangesReply, error) {

	opMetrics := metricStartOp(infra.SegChangesReq)
	reply, err := m.messenger.GetSegChanges(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return reply, err
}

func (m *MessengerWithMetrics) SendSegChangesReply(ctx context.Context,
	msg *path_mgmt.SegChangesReply, a net.Addr, id uint64) error {

	opMetrics := metricStartOp(infra.SegChangesReply)
	err := m.messenger.SendSegChangesReply(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) RequestChainIssue(ctx context.Context, msg *cert_mgmt.ChainIssReq,
	a net.Addr, id uint64) (*cert_mgmt.ChainIssRep, error) {

	opMetrics := metricStartOp(infra.ChainIssueRequest)
	reply, err := m.messenger.RequestChainIssue(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return reply, err
}

func (m *MessengerWithMetrics) SendChainIssueReply(ctx context.Context, msg *cert_mgmt.ChainIssRep,
	a net.Addr, id uint64) error {

	opMetrics := metricStartOp(infra.ChainIssueReply)
	err := m.messenger.SendChainIssueReply(ctx, msg, a, id)
	opMetrics.publishResult(err)
	return err
}

func (m *MessengerWithMetrics) AddHandler(msgType infra.MessageType, handler infra.Handler) {
	handlerWithMetrics := func(request *infra.Request) *infra.HandlerResult {
		inCallsTotal.With(prometheus.Labels{
			prom.LabelOperation: msgType.MetricLabel(),
			prom.LabelSrc:       metricSrcValue(request.Peer, m.ia),
		}).Inc()
		start := time.Now()
		result := handler.Handle(request)
		inResultsTotal.With(prometheus.Labels{
			prom.LabelOperation: msgType.MetricLabel(),
			prom.LabelResult:    result.Result,
		}).Inc()
		inCallsLatency.With(prometheus.Labels{
			prom.LabelOperation: msgType.MetricLabel(),
			prom.LabelStatus:    result.Status,
		}).Observe(time.Since(start).Seconds())
		return result
	}
	m.messenger.AddHandler(msgType, infra.HandlerFunc(handlerWithMetrics))
}

func (m *MessengerWithMetrics) ListenAndServe() {
	m.messenger.ListenAndServe()
}

func (m *MessengerWithMetrics) CloseServer() error {
	return m.messenger.CloseServer()
}

func (m *MessengerWithMetrics) UpdateSigner(signer ctrl.Signer, types []infra.MessageType) {
	m.messenger.UpdateSigner(signer, types)
}

func (m *MessengerWithMetrics) UpdateVerifier(verifier ctrl.SigVerifier) {
	m.messenger.UpdateVerifier(verifier)
}
