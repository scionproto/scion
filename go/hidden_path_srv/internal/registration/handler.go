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

package registration

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

// Validator is used to validate hidden path segments
type Validator interface {
	Validate(*path_mgmt.HPSegReg, addr.IA) error
}

type hpSegRegHandler struct {
	request    *infra.Request
	validator  Validator
	segHandler seghandler.Handler
}

// NewSegRegHandler returns a hidden path segment registration handler
func NewSegRegHandler(validator Validator, segHandler seghandler.Handler) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &hpSegRegHandler{
			request:    r,
			validator:  validator,
			segHandler: segHandler,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// Handle handles a hidden path registration request
func (h *hpSegRegHandler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	res, err := h.handle(logger)
	if err != nil {
		logger.Error("[hpSegRegHandler] Unable to handle request", "err", err)
	}
	return res
}

func (h *hpSegRegHandler) handle(logger log.Logger) (*infra.HandlerResult, error) {
	ctx := h.request.Context()
	hpSegReg, ok := h.request.Message.(*path_mgmt.HPSegReg)
	if !ok {
		logger.Error("[hpSegRegHandler] Wrong message type, expected path_mgmt.HPSegReg",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal, nil
	}
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[hpSegRegHandler] Unable to service request, no Messenger found")
		return infra.MetricsErrInternal, nil
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	if err := hpSegReg.ParseRaw(); err != nil {
		logger.Error("[hpSegRegHandler] Failed to parse message", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid, nil
	}
	logger.Debug("[hpSegRegHandler] Received HPSegRecs", "src",
		h.request.Peer, "data", hpSegReg.HPSegRecs)

	snetPeer, ok := h.request.Peer.(*snet.UDPAddr)
	if !ok {
		logger.Error("[hpSegRegHandler] Invalid peer address type, expected *snet.UDPAddr",
			"peer", h.request.Peer, "type", common.TypeOf(h.request.Peer))
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid, nil
	}
	if err := h.validator.Validate(hpSegReg, snetPeer.IA); err != nil {
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid, nil
	}
	segRecs := seghandler.Segments{
		Segs: hpSegReg.Recs,
		//		HPGroupID: hiddenpath.IdFromMsg(hpSegReg.GroupId),
	}
	res := h.segHandler.Handle(ctx, segRecs, snetPeer)
	if err := res.Err(); err != nil {
		logger.Error("[hpSegRegHandler] Failed to handle path segments", "err", err)
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid, nil
	}
	if len(res.VerificationErrors()) > 0 {
		log.FromCtx(ctx).Info("[hpSegRegHandler] Error during verification of segments/revocations",
			"errors", res.VerificationErrors().ToError())
	}
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk, nil
}
