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
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

type segRegHandler struct {
	*baseHandler
	localIA addr.IA
}

func NewSegRegHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segRegHandler{
			baseHandler: newBaseHandler(r, args),
			localIA:     args.IA,
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segRegHandler) Handle() {
	logger := log.FromCtx(h.request.Context())
	segReg, ok := h.request.Message.(*path_mgmt.SegReg)
	if !ok {
		logger.Error("[segRegHandler] wrong message type, expected path_mgmt.SegReg",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Error("[segRegHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	sendAck := messenger.SendAckHelper(subCtx, msger, h.request.Peer, h.request.ID)
	if err := segReg.ParseRaw(); err != nil {
		logger.Error("[segRegHandler] Failed to parse message", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return
	}
	logSegRecs(logger, "[segRegHandler]", h.request.Peer, segReg.SegRecs)
	h.verifyAndStore(subCtx, h.request.Peer, segReg.Recs, segReg.SRevInfos)
	// TODO(lukedirtwalker): If all segments failed to verify the ack should also be negative here.
	sendAck(proto.Ack_ErrCode_ok, "")
}
