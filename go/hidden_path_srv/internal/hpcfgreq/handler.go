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

package hpcfgreq

import (
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

type handler struct {
	request *infra.Request
	localIA addr.IA
	// localGroups contains all groups of which the local IA is a reader
	localGroups []*path_mgmt.HPCfg
}

// NewHandler returns a hidden path configuration request handler
func NewHandler(groups []*hiddenpath.Group, localIA addr.IA) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &handler{
			request:     r,
			localGroups: filterGroups(groups, localIA),
			localIA:     localIA,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// Handle handles a hidden path configuration request
// It replies to clients in the same AS with all hidden path group configurations
// of which the AS is a reader.
func (h *handler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	res, err := h.handle(logger)
	if err != nil {
		logger.Error("[hpCfgReqHandler] Unable to handle request", "err", err)
	}
	return res
}

func (h *handler) handle(logger log.Logger) (*infra.HandlerResult, error) {
	ctx := h.request.Context()
	hpCfgReq, ok := h.request.Message.(*path_mgmt.HPCfgReq)
	if !ok {
		logger.Error("[hpCfgReqHandler] Wrong message type, expected path_mgmt.HPCfgReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal, nil
	}
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[hpCfgReqHandler] Unable to service request, no Messenger found")
		return infra.MetricsErrInternal, nil
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	logger.Debug("[hpCfgReqHandler] Received HPCfgReq", "src", h.request.Peer, "req", hpCfgReq)

	snetPeer, ok := h.request.Peer.(*snet.UDPAddr)
	if !ok {
		logger.Error("[hpCfgReqHandler] Invalid peer address type, expected *snet.UDPAddr",
			"peer", h.request.Peer, "type", common.TypeOf(h.request.Peer))
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid, nil
	}

	if snetPeer.IA != h.localIA {
		logger.Error("[hpCfgReqHandler] Not handling non-local requests")
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		return infra.MetricsErrInvalid, nil
	}

	reply := &path_mgmt.HPCfgReply{Cfgs: h.localGroups}

	if err := rw.SendHPCfgReply(ctx, reply); err != nil {
		logger.Error("[hpSegReqHandler] Failed to send reply", "err", err)
		return infra.MetricsErrInternal, nil
	}
	logger.Debug("[hpSegReqHandler] Replied with configurations", "cfgs", len(reply.Cfgs))
	return infra.MetricsResultOk, nil
}

func filterGroups(groups []*hiddenpath.Group, localIA addr.IA) []*path_mgmt.HPCfg {
	var local = []*path_mgmt.HPCfg{}
	for _, g := range groups {
		if g.Owner == localIA || g.HasReader(localIA) || g.HasWriter(localIA) {
			local = append(local, g.ToMsg())
		}
	}
	return local
}
