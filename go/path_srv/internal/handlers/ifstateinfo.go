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
	"github.com/scionproto/scion/go/lib/log"
)

type ifStateInfoHandler struct {
	*baseHandler
}

func NewIfStatInfoHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &ifStateInfoHandler{
			baseHandler: newBaseHandler(r, args),
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *ifStateInfoHandler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	ifStateInfo, ok := h.request.Message.(*path_mgmt.IFStateInfos)
	if !ok {
		logger.Error("[ifStateHandler] wrong message type, expected path_mgmt.IFStateInfos",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	logger.Debug("[ifStateHandler] Received IfStateInfo", "ifStateInfo", ifStateInfo)
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	// TODO(lukedirtwalker): if all verifications fail we should reflect that in metrics.
	for _, info := range ifStateInfo.Infos {
		if !info.Active && info.SRevInfo != nil {
			h.verifyAndStore(subCtx, info.SRevInfo)
		}
	}
	logger.Debug("[ifStateHandler] done processing ifStateInfo")
	return infra.MetricsResultOk
}

func (h *ifStateInfoHandler) verifyAndStore(ctx context.Context, rev *path_mgmt.SignedRevInfo) {
	logger := log.FromCtx(ctx)
	err := segverifier.VerifyRevInfo(ctx, h.trustStore, h.request.Peer, rev)
	if err != nil {
		logger.Error("[ifStateHandler] Failed to verify revInfo", "rev", rev, "err", err)
		return
	}
	_, err = h.revCache.Insert(ctx, rev)
	if err != nil {
		logger.Error("[ifStateHandler] Failed to insert revInfo", "rev", rev, "err", err)
	}
}
