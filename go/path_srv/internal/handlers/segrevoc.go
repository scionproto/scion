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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

type revocHandler struct {
	*baseHandler
	NextQueryCleaner segfetcher.NextQueryCleaner
}

func NewRevocHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &revocHandler{
			baseHandler: newBaseHandler(r, args),
			NextQueryCleaner: segfetcher.NextQueryCleaner{
				PathDB: args.PathDB,
			},
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *revocHandler) Handle() *infra.HandlerResult {
	ctx := h.request.Context()
	logger := log.FromCtx(ctx)
	logger = logger.New("from", h.request.Peer)
	revocation, ok := h.request.Message.(*path_mgmt.SignedRevInfo)
	if !ok {
		logger.Error("[revocHandler] wrong message type, expected path_mgmt.SignedRevInfo",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[revocHandler] Unable to service request, no Messenger found")
		return infra.MetricsErrInternal
	}
	logger = logger.New("signer", revocation.Sign.Src)

	sendAck := messenger.SendAckHelper(ctx, rw)
	revInfo, err := revocation.RevInfo()
	if err != nil {
		logger.Warn("[revocHandler] Couldn't parse revocation", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid
	}
	logger = logger.New("revInfo", revInfo)
	logger.Debug("[revocHandler] Received revocation")

	err = segverifier.VerifyRevInfo(ctx, h.verifierFactory.NewVerifier(), nil, revocation)
	if err != nil {
		logger.Warn("Couldn't verify revocation", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		return infra.MetricsErrInvalid
	}
	// if err := h.NextQueryCleaner.ResetQueryCache(ctx, revInfo); err != nil {
	// 	logger.Warn("Couldn't reset pathdb cache for revocation", "err", err)
	// }

	_, err = h.revCache.Insert(ctx, revocation)
	if err != nil {
		logger.Error("Failed to insert revInfo", "err", err)
		sendAck(proto.Ack_ErrCode_retry, messenger.AckRetryDBError)
		return infra.MetricsErrRevCache(err)
	}
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk
}
