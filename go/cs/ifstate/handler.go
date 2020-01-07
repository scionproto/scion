// Copyright 2019 Anapaya Systems
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

package ifstate

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
)

type handler struct {
	intfs   *Interfaces
	request *infra.Request
}

// NewHandler creates interface state request handler.
func NewHandler(intfs *Interfaces) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &handler{
			intfs:   intfs,
			request: r,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *handler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	ifStateReq, ok := h.request.Message.(*path_mgmt.IFStateReq)
	if !ok {
		logger.Error("[IfStateReqHandler] Wrong message type",
			"type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	logger.Debug("[IfStateReqHandler] Received", "ifStateReq", ifStateReq)
	rw, ok := infra.ResponseWriterFromContext(h.request.Context())
	if !ok {
		logger.Error("[IfStateReqHandler] No response writer")
		return infra.MetricsErrInternal
	}
	reply := h.buildIfStateInfo(ifStateReq)
	if err := rw.SendIfStateInfoReply(h.request.Context(), reply); err != nil {
		logger.Error("[IfStateReqHandler] Failed to send reply", "err", err)
		return infra.MetricsErrMsger(err)
	}
	return infra.MetricsResultOk
}

func (h *handler) buildIfStateInfo(req *path_mgmt.IFStateReq) *path_mgmt.IFStateInfos {
	var infos []*path_mgmt.IFStateInfo
	if req.IfID != 0 {
		infos = []*path_mgmt.IFStateInfo{infoFromInterface(req.IfID, h.intfs.Get(req.IfID))}
	} else {
		all := h.intfs.All()
		infos = make([]*path_mgmt.IFStateInfo, 0, len(all))
		for ifid, intf := range all {
			infos = append(infos, infoFromInterface(ifid, intf))
		}
	}
	return &path_mgmt.IFStateInfos{Infos: infos}
}

func infoFromInterface(ifid common.IFIDType, intf *Interface) *path_mgmt.IFStateInfo {
	return &path_mgmt.IFStateInfo{
		IfID:     ifid,
		Active:   intf.State() == Active,
		SRevInfo: intf.Revocation(),
	}
}
