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

type revocHandler struct {
	*baseHandler
}

func NewRevocHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &revocHandler{
			baseHandler: newBaseHandler(r, args),
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *revocHandler) Handle() {
	revocation, ok := h.request.Message.(*path_mgmt.SignedRevInfo)
	if !ok {
		h.logger.Error("[revocHandler] wrong message type, expected path_mgmt.SignedRevInfo",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	h.logger.Debug("[revocHandler] Received message", "revocation", revocation)
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	h.verifyAndStore(subCtx, revocation)
}

func (h *revocHandler) verifyAndStore(ctx context.Context, revocation *path_mgmt.SignedRevInfo) {
	err := segverifier.VerifyRevInfo(ctx, h.trustStore, h.request.Peer, revocation)
	if err != nil {
		h.logger.Warn("[revocHandler] couldn't verify revocation", "err", err)
		return
	}
	h.revCache.Insert(revocation)
}
