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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
)

type segRegHandler struct {
	*baseHandler
}

func NewSegRegHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segRegHandler{
			baseHandler: newBaseHandler(r, args),
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segRegHandler) Handle() {
	segReg, ok := h.request.Message.(*path_mgmt.SegReg)
	if !ok {
		h.logger.Error("[segRegHandler] wrong message type, expected path_mgmt.SegReg",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	if err := segReg.ParseRaw(); err != nil {
		h.logger.Error("[segRegHandler] Failed to parse message", "err", err)
		return
	}
	h.logger.Debug("[segRegHandler] Received message", "seg", segReg.SegRecs)
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	h.verifyAndStore(subCtx, h.request.Peer, segReg.Recs, segReg.SRevInfos)
}
