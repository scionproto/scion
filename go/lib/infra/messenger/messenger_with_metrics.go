// Copyright 2019 ETH Zurich, Anapaya Systems
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

	return observe(ctx, infra.Ack, func(ctx context.Context) error {
		return m.messenger.SendAck(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq,
	a net.Addr, id uint64) (*cert_mgmt.TRC, error) {

	var trc *cert_mgmt.TRC
	return trc, observe(ctx, infra.TRCRequest, func(ctx context.Context) error {
		var err error
		trc, err = m.messenger.GetTRC(ctx, msg, a, id)
		return err
	})
}

func (m *MessengerWithMetrics) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr,
	id uint64) error {

	return observe(ctx, infra.TRC, func(ctx context.Context) error {
		return m.messenger.SendTRC(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr, id uint64) (*cert_mgmt.Chain, error) {

	var chain *cert_mgmt.Chain
	return chain, observe(ctx, infra.ChainRequest, func(ctx context.Context) error {
		var err error
		chain, err = m.messenger.GetCertChain(ctx, msg, a, id)
		return err
	})
}

func (m *MessengerWithMetrics) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr,
	id uint64) error {

	return observe(ctx, infra.Chain, func(ctx context.Context) error {
		return m.messenger.SendCertChain(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) SendIfId(ctx context.Context, msg *ifid.IFID, a net.Addr,
	id uint64) error {

	return observe(ctx, infra.IfId, func(ctx context.Context) error {
		return m.messenger.SendIfId(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) SendIfStateInfos(ctx context.Context, msg *path_mgmt.IFStateInfos,
	a net.Addr, id uint64) error {

	return observe(ctx, infra.IfStateInfos, func(ctx context.Context) error {
		return m.messenger.SendIfStateInfos(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) SendRev(ctx context.Context, msg *path_mgmt.SignedRevInfo,
	a net.Addr, id uint64) error {

	return observe(ctx, infra.SignedRev, func(ctx context.Context) error {
		return m.messenger.SendRev(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) SendSegReg(ctx context.Context, msg *path_mgmt.SegReg,
	a net.Addr, id uint64) error {

	return observe(ctx, infra.SegReg, func(ctx context.Context) error {
		return m.messenger.SendSegReg(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) GetSegs(ctx context.Context, msg *path_mgmt.SegReq,
	a net.Addr, id uint64) (*path_mgmt.SegReply, error) {

	var segs *path_mgmt.SegReply
	return segs, observe(ctx, infra.SegRequest, func(ctx context.Context) error {
		var err error
		segs, err = m.messenger.GetSegs(ctx, msg, a, id)
		return err
	})
}

func (m *MessengerWithMetrics) SendSegReply(ctx context.Context, msg *path_mgmt.SegReply,
	a net.Addr, id uint64) error {

	return observe(ctx, infra.SegReply, func(ctx context.Context) error {
		return m.messenger.SendSegReply(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) SendSegSync(ctx context.Context, msg *path_mgmt.SegSync,
	a net.Addr, id uint64) error {

	return observe(ctx, infra.SegSync, func(ctx context.Context) error {
		return m.messenger.SendSegSync(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) GetSegChangesIds(ctx context.Context, msg *path_mgmt.SegChangesIdReq,
	a net.Addr, id uint64) (*path_mgmt.SegChangesIdReply, error) {

	var reply *path_mgmt.SegChangesIdReply
	return reply, observe(ctx, infra.SegChangesIdReq, func(ctx context.Context) error {
		var err error
		reply, err = m.GetSegChangesIds(ctx, msg, a, id)
		return err
	})
}

func (m *MessengerWithMetrics) SendSegChangesIdReply(ctx context.Context,
	msg *path_mgmt.SegChangesIdReply, a net.Addr, id uint64) error {

	return observe(ctx, infra.SegChangesIdReply, func(ctx context.Context) error {
		return m.messenger.SendSegChangesIdReply(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) GetSegChanges(ctx context.Context, msg *path_mgmt.SegChangesReq,
	a net.Addr, id uint64) (*path_mgmt.SegChangesReply, error) {

	var reply *path_mgmt.SegChangesReply
	return reply, observe(ctx, infra.SegChangesReq, func(ctx context.Context) error {
		var err error
		reply, err = m.GetSegChanges(ctx, msg, a, id)
		return err
	})
}

func (m *MessengerWithMetrics) SendSegChangesReply(ctx context.Context,
	msg *path_mgmt.SegChangesReply, a net.Addr, id uint64) error {

	return observe(ctx, infra.SegChangesReply, func(ctx context.Context) error {
		return m.messenger.SendSegChangesReply(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) RequestChainIssue(ctx context.Context, msg *cert_mgmt.ChainIssReq,
	a net.Addr, id uint64) (*cert_mgmt.ChainIssRep, error) {

	var reply *cert_mgmt.ChainIssRep
	return reply, observe(ctx, infra.ChainIssueRequest, func(ctx context.Context) error {
		var err error
		reply, err = m.RequestChainIssue(ctx, msg, a, id)
		return err
	})
}

func (m *MessengerWithMetrics) SendChainIssueReply(ctx context.Context, msg *cert_mgmt.ChainIssRep,
	a net.Addr, id uint64) error {

	return observe(ctx, infra.ChainIssueReply, func(ctx context.Context) error {
		return m.messenger.SendChainIssueReply(ctx, msg, a, id)
	})
}

func (m *MessengerWithMetrics) SendBeacon(ctx context.Context, msg *seg.Beacon, a net.Addr,
	id uint64) error {

	return observe(ctx, infra.Seg, func(ctx context.Context) error {
		return m.messenger.SendBeacon(ctx, msg, a, id)
	})
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

func (m *MessengerWithMetrics) UpdateSigner(signer infra.Signer, types []infra.MessageType) {
	m.messenger.UpdateSigner(signer, types)
}

func (m *MessengerWithMetrics) UpdateVerifier(verifier infra.Verifier) {
	m.messenger.UpdateVerifier(verifier)
}
