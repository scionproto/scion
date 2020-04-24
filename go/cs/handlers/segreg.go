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
	"github.com/scionproto/scion/go/cs/metrics"
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
	labels := metrics.RegistrationLabels{
		Result: metrics.ErrInternal,
	}
	segReg, ok := h.request.Message.(*path_mgmt.SegReg)
	if !ok {
		logger.Error("[segRegHandler] wrong message type, expected path_mgmt.SegReg",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		metrics.Registrations.ResultsTotal(labels).Inc()
		return infra.MetricsErrInternal
	}
	snetPeer := h.request.Peer.(*snet.UDPAddr)
	labels.Type = classifySegs(logger, segReg)
	labels.Src = snetPeer.IA
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[segRegHandler] Unable to service request, no ReplyWriter found")
		metrics.Registrations.ResultsTotal(labels).Inc()
		return infra.MetricsErrInternal
	}
	labels.Result = metrics.ErrParse
	sendAck := messenger.SendAckHelper(ctx, rw)
	if err := segReg.ParseRaw(); err != nil {
		logger.Error("[segRegHandler] Failed to parse message", "err", err)
		metrics.Registrations.ResultsTotal(labels).Inc()
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid
	}
	logSegRecs(logger, "[segRegHandler]", h.request.Peer, segReg.SegRecs)

	peerPath, err := snetPeer.GetPath()
	if err != nil {
		logger.Error("[segRegHandler] Failed to initialize path", "err", err)
		metrics.Registrations.ResultsTotal(labels).Inc()
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid
	}
	svcToQuery := &snet.SVCAddr{
		IA:      snetPeer.IA,
		Path:    peerPath.Path(),
		NextHop: peerPath.UnderlayNextHop(),
		SVC:     addr.SvcBS,
	}
	segs := seghandler.Segments{
		Segs:      segReg.Recs,
		SRevInfos: segReg.SRevInfos,
	}
	res := h.handler.Handle(ctx, segs, svcToQuery, nil)
	// wait until processing is done.
	<-res.FullReplyProcessed()
	if err := res.Err(); err != nil {
		// TODO(lukedirtwalker): classify crypto/db error
		labels.Result = metrics.ErrCrypto
		metrics.Registrations.ResultsTotal(labels).Inc()
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid
	}
	if len(res.VerificationErrors()) > 0 {
		log.FromCtx(ctx).Warn("[segRegHandler] Error during verification of segments/revocations",
			"errors", res.VerificationErrors().ToError())
	}
	h.incMetrics(labels, res.Stats())
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk
}

func (h *segRegHandler) incMetrics(labels metrics.RegistrationLabels, stats seghandler.Stats) {
	labels.Result = metrics.OkRegistrationNew
	metrics.Registrations.ResultsTotal(labels).Add(float64(stats.SegsInserted()))
	labels.Result = metrics.OkRegiststrationUpdated
	metrics.Registrations.ResultsTotal(labels).Add(float64(stats.SegsUpdated()))
}

// classifySegs determines the type of segments that are registered. In the
// current implementation there should always be exactly 1 entry so 1 type can
// be returned. However the type allows multiple segments to be registered, so
// this function will concatenate the types if there are multiple segments of
// different types.
func classifySegs(logger log.Logger, segReg *path_mgmt.SegReg) proto.PathSegType {
	segTypes := make(map[proto.PathSegType]struct{}, 1)
	for _, segMeta := range segReg.Recs {
		segTypes[segMeta.Type] = struct{}{}
	}
	if len(segTypes) > 1 {
		logger.Warn("SegReg contained multiple types, reporting unset in metrics",
			"types", segTypes)
		return proto.PathSegType_unset
	}
	for segType := range segTypes {
		return segType
	}
	return proto.PathSegType_unset
}
