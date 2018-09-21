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
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
)

type ifStateInfoHandler struct {
	*baseHandler
}

func NewIfStatInfoHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &ifStateInfoHandler{
			baseHandler: newBaseHandler(r, args),
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *ifStateInfoHandler) Handle() {
	ifStateInfo, ok := h.request.Message.(*path_mgmt.IFStateInfos)
	if !ok {
		h.logger.Error("[ifStateHandler] wrong message type, expected path_mgmt.IFStateInfos",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	h.logger.Debug("[ifStateHandler] Received IfStateInfo", "ifStateInfo", ifStateInfo)
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	for _, info := range ifStateInfo.Infos {
		if !info.Active && info.SRevInfo != nil {
			h.verifyAndStore(subCtx, info.SRevInfo)
		}
	}
	h.logger.Debug("[ifStateHandler] done processing ifStateInfo")
}

func (h *ifStateInfoHandler) verifyAndStore(ctx context.Context, rev *path_mgmt.SignedRevInfo) {
	err := segverifier.VerifyRevInfo(ctx, h.trustStore, h.request.Peer, rev)
	if err != nil {
		h.logger.Error("[ifStateHandler] Failed to verify revInfo", "rev", rev, "err", err)
		return
	}
	h.revCache.Insert(rev)
}
