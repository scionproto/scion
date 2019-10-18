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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

type hpCfgReqHandler struct {
	request *infra.Request
	// groupMap maps ASes to all groups of which they are a reader
	groupMap map[addr.IA][]*path_mgmt.HPCfg
	localIA  addr.IA
}

// NewCfgReqHandler returns a hidden path configuration request handler
func NewCfgReqHandler(groups []*hiddenpath.Group, ia addr.IA) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &hpCfgReqHandler{
			request:  r,
			groupMap: createMap(groups),
			localIA:  ia,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// Handle handles a hidden path configuration request
func (h *hpCfgReqHandler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	res, err := h.handle(logger)
	if err != nil {
		logger.Error("[hpCfgReqHandler] Unable to handle request", "err", err)
	}
	return res
}

func (h *hpCfgReqHandler) handle(logger log.Logger) (*infra.HandlerResult, error) {
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

	snetPeer, ok := h.request.Peer.(*snet.Addr)
	if !ok {
		logger.Error("[hpCfgReqHandler] Invalid peer address type, expected *snet.Addr", nil,
			"peer", h.request.Peer, "type", common.TypeOf(h.request.Peer))
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid, nil
	}

	if snetPeer.IA != h.localIA {
		logger.Error("[hpCfgReqHandler] Not handling non-local requests")
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		return infra.MetricsErrInvalid, nil
	}

	reply := &path_mgmt.HPCfgReply{Cfgs: h.groupMap[snetPeer.IA]}

	if err := rw.SendHPCfgReply(ctx, reply); err != nil {
		logger.Error("[hpSegReqHandler] Failed to send reply", "err", err)
		return infra.MetricsErrInternal, nil
	}
	logger.Debug("[hpSegReqHandler] Replied with configurations", "cfgs", len(reply.Cfgs))
	return infra.MetricsResultOk, nil
}

func createMap(groups []*hiddenpath.Group) map[addr.IA][]*path_mgmt.HPCfg {
	m := make(map[addr.IA][]*path_mgmt.HPCfg)
	for _, g := range groups {
		m[g.Owner] = append(m[g.Owner], g.ToMsg())
		for _, reader := range g.Readers {
			m[reader] = append(m[reader], g.ToMsg())
		}
		for _, writer := range g.Writers {
			m[writer] = append(m[writer], g.ToMsg())
		}
	}
	return m
}
