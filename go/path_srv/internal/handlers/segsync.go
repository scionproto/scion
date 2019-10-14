// Copyright 2018 Anapaya Systems
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

package handlers

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/path_srv/internal/metrics"
	"github.com/scionproto/scion/go/proto"
)

type syncHandler struct {
	*baseHandler
	localIA addr.IA
	handler seghandler.Handler
}

func NewSyncHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &syncHandler{
			baseHandler: newBaseHandler(r, args),
			localIA:     args.IA,
			handler: seghandler.Handler{
				Verifier: &seghandler.DefaultVerifier{
					Verifier: args.VerifierFactory.NewVerifier(),
				},
				Storage: &seghandler.DefaultStorage{
					PathDB:   args.PathDB,
					RevCache: args.RevCache,
				},
			},
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *syncHandler) Handle() *infra.HandlerResult {
	ctx := h.request.Context()
	logger := log.FromCtx(ctx)
	labels := metrics.SyncRegLabels{
		Result: metrics.ErrInternal,
	}
	segSync, ok := h.request.Message.(*path_mgmt.SegSync)
	if !ok {
		logger.Error("[syncHandler] wrong message type, expected path_mgmt.SegSync",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		metrics.Syncs.Registrations(labels).Inc()
		return infra.MetricsErrInternal
	}
	snetPeer := h.request.Peer.(*snet.Addr)
	labels.Src = snetPeer.IA
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[syncHandler] Unable to service request, no Messenger found")
		metrics.Syncs.Registrations(labels).Inc()
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	if err := segSync.ParseRaw(); err != nil {
		logger.Error("[syncHandler] Failed to parse message", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		metrics.Syncs.Registrations(labels.WithResult(metrics.ErrParse)).Inc()
		return infra.MetricsErrInvalid
	}
	logSegRecs(logger, "[syncHandler]", h.request.Peer, segSync.SegRecs)
	peerPath, err := snetPeer.GetPath()
	if err != nil {
		logger.Error("[syncHandler] Failed to initialize path", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		metrics.Syncs.Registrations(labels.WithResult(metrics.ErrParse)).Inc()
		return infra.MetricsErrInvalid
	}
	svcToQuery := &snet.Addr{
		IA:      snetPeer.IA,
		Path:    peerPath.Path(),
		NextHop: peerPath.OverlayNextHop(),
		Host:    addr.NewSVCUDPAppAddr(addr.SvcPS),
	}
	segs := seghandler.Segments{
		Segs:      segSync.Recs,
		SRevInfos: segSync.SRevInfos,
	}
	res := h.handler.Handle(ctx, segs, svcToQuery, nil)
	// wait until processing is done.
	<-res.FullReplyProcessed()
	if err := res.Err(); err != nil {
		// TODO(lukedirtwalker): classify error (https://github.com/scionproto/scion/issues/3240)
		metrics.Syncs.Registrations(labels).Inc()
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid
	}
	metrics.Syncs.RegistrationSuccess(labels, res.Stats())
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk
}
