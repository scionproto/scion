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

// SegSync handles down segment synchronization.
type SegSync struct {
	SegHandler seghandler.Handler
}

// Handle handles a down segment synchronization message.
func (h *SegSync) Handle(request *infra.Request) *infra.HandlerResult {
	ctx := request.Context()
	logger := log.FromCtx(ctx)
	labels := metrics.SyncRegLabels{
		Result: metrics.ErrInternal,
	}
	segSync, ok := request.Message.(*path_mgmt.SegSync)
	if !ok {
		logger.Error("[syncHandler] wrong message type, expected path_mgmt.SegSync",
			"msg", request.Message, "type", common.TypeOf(request.Message))
		metrics.Sync.Registrations(labels).Inc()
		return infra.MetricsErrInternal
	}
	snetPeer := request.Peer.(*snet.UDPAddr)
	labels.Src = snetPeer.IA
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[syncHandler] Unable to service request, no Messenger found")
		metrics.Sync.Registrations(labels).Inc()
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	if err := segSync.ParseRaw(); err != nil {
		logger.Error("[syncHandler] Failed to parse message", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		metrics.Sync.Registrations(labels.WithResult(metrics.ErrParse)).Inc()
		return infra.MetricsErrInvalid
	}
	logSegRecs(logger, "[syncHandler]", request.Peer, segSync.SegRecs)
	peerPath, err := snetPeer.GetPath()
	if err != nil {
		logger.Error("[syncHandler] Failed to initialize path", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		metrics.Sync.Registrations(labels.WithResult(metrics.ErrParse)).Inc()
		return infra.MetricsErrInvalid
	}
	svcToQuery := &snet.SVCAddr{
		IA:      snetPeer.IA,
		Path:    peerPath.Path(),
		NextHop: peerPath.UnderlayNextHop(),
		SVC:     addr.SvcPS,
	}

	segs := seghandler.Segments{
		Segs:      segSync.Recs,
		SRevInfos: segSync.SRevInfos,
	}
	res := h.SegHandler.Handle(ctx, segs, svcToQuery, nil)
	// wait until processing is done.
	<-res.FullReplyProcessed()
	if err := res.Err(); err != nil {
		metrics.Sync.Registrations(labels.WithResult(metrics.ErrDB)).Inc()
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid
	}
	if len(res.VerificationErrors()) > 0 {
		log.FromCtx(ctx).Info("[syncHandler] Error during verification of segments/revocations",
			"errors", res.VerificationErrors().ToError())
	}
	metrics.Sync.RegistrationSuccess(labels,
		res.Stats().SegsInserted(),
		res.Stats().SegsUpdated())
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk
}
