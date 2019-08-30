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

package handlers

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

type hpSegRegHandler struct {
	*baseHandler
}

// NewSegRegHandler returns a hidden path segment registration handler
func NewSegRegHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &hpSegRegHandler{
			baseHandler: newBaseHandler(r, args),
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
	hpSegReg, ok := h.request.Message.(*path_mgmt.HPSegReg)
	if !ok {
		logger.Error("[hpSegRegHandler] wrong message type, expected path_mgmt.HPSegReg",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
	}
	rw, ok := infra.ResponseWriterFromContext(h.request.Context())
	if !ok {
		logger.Error("[hpSegRegHandler] Unable to service request, no Messenger found")
		return infra.MetricsErrInternal, nil
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	sendAck := messenger.SendAckHelper(subCtx, rw)
	if err := hpSegReg.ParseRaw(); err != nil {
		logger.Error("[hpSegRegHandler] Failed to parse message", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid, nil
	}
	logHPSegRecs(logger, "[hpSegRegHandler]", h.request.Peer, hpSegReg.HPSegRecs)

	snetPeer := h.request.Peer.(*snet.Addr)
	peerPath, err := snetPeer.GetPath()
	if err != nil {
		logger.Error("[hpSegRegHandler] Failed to initialize path", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid, nil
	}
	svcToQuery := &snet.Addr{
		IA:      snetPeer.IA,
		Path:    peerPath.Path(),
		NextHop: peerPath.OverlayNextHop(),
		Host:    addr.NewSVCUDPAppAddr(addr.SvcBS),
	}
	if err := h.verifyAndStore(subCtx, svcToQuery, hpSegReg); err != nil {
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid, nil
	}
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk, nil
}
