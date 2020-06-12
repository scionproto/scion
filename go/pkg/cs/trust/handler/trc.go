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

package handler

import (
	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/pkg/cs/trust/internal/metrics"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

// TRCReq handles TRC requests.
type TRCReq struct {
	Provider trust.Provider
	IA       addr.IA
}

// Handle handles a TRC request.
func (h TRCReq) Handle(req *infra.Request) *infra.HandlerResult {
	l := metrics.HandlerLabels{ReqType: metrics.TRCReq, Client: infra.PromSrcUnknown}
	if req == nil {
		log.Error("[trust:TRCReq] Request is nil")
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	l.Client = metrics.PeerToLabel(req.Peer, h.IA)

	span, ctx := opentracing.StartSpanFromContext(req.Context(), "trusthandler.trc_request")
	defer span.Finish()
	logger := log.FromCtx(ctx)

	trcReq, ok := req.Message.(*cert_mgmt.TRCReq)
	if !ok {
		logger.Error("[trust:TRCReq] Wrong message type, expected cert_mgmt.TRCReq",
			"msg", req.Message, "type", common.TypeOf(req.Message))
		setHandlerMetric(span, l.WithResult(metrics.ErrInternal), errWrongMsgType)
		return infra.MetricsErrInternal
	}

	logger.Debug("[trust:TRCReq] Received request", "trcReq", trcReq, "peer", req.Peer)
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[trust:TRCReq] Unable to service request, no ResponseWriter found")
		setHandlerMetric(span, l.WithResult(metrics.ErrInternal), errNoResponseWriter)
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	trc, err := h.Provider.GetSignedTRC(ctx,
		trcReq.ID(),
		trust.AllowInactive(),
		trust.Client(req.Peer),
	)
	if err != nil {
		logger.Error("[trust:TRCReq] Unable to retrieve TRC", "err", err)
		sendAck(proto.Ack_ErrCode_reject, AckNotFound)
		setHandlerMetric(span, l.WithResult(metrics.ErrInternal), err)
		return infra.MetricsErrTrustStore(err)
	}
	if err = rw.SendTRCReply(ctx, &cert_mgmt.TRC{RawTRC: trc.Raw}); err != nil {
		logger.Error("[trust:TRCReq] Messenger API error", "err", err)
		setHandlerMetric(span, l.WithResult(metrics.ErrTransmit), err)
		return infra.MetricsErrMsger(err)
	}
	logger.Debug("[trust:TRCReq] Replied with TRC")
	setHandlerMetric(span, l.WithResult(metrics.Success), nil)
	return infra.MetricsResultOk
}
