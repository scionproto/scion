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

package hpsegreq

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

type hpSegReqHandler struct {
	request *infra.Request
	fetcher Fetcher
}

// NewSegReqHandler returns a hidden path segment request handler
func NewSegReqHandler(fetcher Fetcher) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &hpSegReqHandler{
			request: r,
			fetcher: fetcher,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// Handle handles a hidden path segment request
func (h *hpSegReqHandler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	res, err := h.handle(logger)
	if err != nil {
		logger.Error("[hpSegReqHandler] Unable to handle request", "err", err)
	}
	return res
}

func (h *hpSegReqHandler) handle(logger log.Logger) (*infra.HandlerResult, error) {
	ctx := h.request.Context()
	hpSegReq, ok := h.request.Message.(*path_mgmt.HPSegReq)
	if !ok {
		logger.Error("[hpSegReqHandler] Wrong message type, expected path_mgmt.HPSegReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal, nil
	}
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[hpSegReqHandler] Unable to service request, no Messenger found")
		return infra.MetricsErrInternal, nil
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	logger.Debug("[hpSegReqHandler] Received HPSegReq", "src", h.request.Peer, "req", hpSegReq)

	snetPeer, ok := h.request.Peer.(*snet.UDPAddr)
	if !ok {
		logger.Error("[hpSegReqHandler] Invalid peer address type, expected *snet.UDPAddr",
			"peer", h.request.Peer, "type", common.TypeOf(h.request.Peer))
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid, nil
	}

	recs, err := h.fetcher.Fetch(ctx, hpSegReq, snetPeer)
	if err != nil {
		logger.Error("[hpSegReqHandler] Fetching hidden segments failed", "err", err)
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid, nil
	}
	reply := &path_mgmt.HPSegReply{
		Recs: recs,
	}
	numSegs := 0
	for _, r := range recs {
		numSegs += len(r.Recs)
	}
	if err = rw.SendHPSegReply(ctx, reply); err != nil {
		logger.Error("[hpSegReqHandler] Failed to send reply", "err", err)
		return infra.MetricsErrInternal, nil
	}
	logger.Debug("[hpSegReqHandler] Replied with segments", "segs", numSegs)
	return infra.MetricsResultOk, nil
}
