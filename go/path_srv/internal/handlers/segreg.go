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
	"github.com/scionproto/scion/go/proto"
)

type segRegHandler struct {
	*baseHandler
	localIA addr.IA
	handler seghandler.Handler
}

func NewSegRegHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &segRegHandler{
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

func (h *segRegHandler) Handle() *infra.HandlerResult {
	ctx := h.request.Context()
	logger := log.FromCtx(ctx)
	segReg, ok := h.request.Message.(*path_mgmt.SegReg)
	if !ok {
		logger.Error("[segRegHandler] wrong message type, expected path_mgmt.SegReg",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[segRegHandler] Unable to service request, no Messenger found")
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	if err := segReg.ParseRaw(); err != nil {
		logger.Error("[segRegHandler] Failed to parse message", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid
	}
	logSegRecs(logger, "[segRegHandler]", h.request.Peer, segReg.SegRecs)

	snetPeer := h.request.Peer.(*snet.Addr)
	peerPath, err := snetPeer.GetPath()
	if err != nil {
		logger.Error("[syncHandler] Failed to initialize path", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid
	}
	svcToQuery := &snet.Addr{
		IA:      snetPeer.IA,
		Path:    peerPath.Path(),
		NextHop: peerPath.OverlayNextHop(),
		Host:    addr.NewSVCUDPAppAddr(addr.SvcBS),
	}
	segs := seghandler.Segments{
		Segs:      segReg.Recs,
		SRevInfos: segReg.SRevInfos,
	}
	res := h.handler.Handle(ctx, segs, svcToQuery, nil)
	// wait until processing is done.
	<-res.FullReplyProcessed()
	if err := res.Err(); err != nil {
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid
	}
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk
}
