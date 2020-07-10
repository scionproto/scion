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
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/proto"
)

type RevocHandler struct {
	RevCache revcache.RevCache
	Verifier infra.Verifier
}

func (h *RevocHandler) Handle(request *infra.Request) *infra.HandlerResult {
	ctx := request.Context()
	logger := log.FromCtx(ctx).New("from", request.Peer)
	labels := metrics.PSRevocationLabels{
		Result: metrics.ErrInternal,
		Src:    metrics.RevSrcNotification,
	}
	revocation, ok := request.Message.(*path_mgmt.SignedRevInfo)
	if !ok {
		logger.Error("[revocHandler] wrong message type, expected path_mgmt.SignedRevInfo",
			"msg", request.Message, "type", common.TypeOf(request.Message))
		metrics.PSRevocation.Count(labels).Inc()
		return infra.MetricsErrInternal
	}
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[revocHandler] Unable to service request, no Messenger found")
		metrics.PSRevocation.Count(labels).Inc()
		return infra.MetricsErrInternal
	}
	logger = logger.New("signer", revocation.Sign.Src)

	sendAck := messenger.SendAckHelper(ctx, rw)
	revInfo, err := revocation.RevInfo()
	if err != nil {
		logger.Info("[revocHandler] Revocation parsing failed", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		metrics.PSRevocation.Count(labels.WithResult(metrics.ErrParse)).Inc()
		return infra.MetricsErrInvalid
	}
	logger = logger.New("revInfo", revInfo)
	logger.Debug("[revocHandler] Received revocation")

	err = segverifier.VerifyRevInfo(ctx, h.Verifier, nil, revocation)
	if err != nil {
		logger.Info("Revocation verification failed", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		metrics.PSRevocation.Count(labels.WithResult(metrics.ErrCrypto)).Inc()
		return infra.MetricsErrInvalid
	}
	_, err = h.RevCache.Insert(ctx, revocation)
	if err != nil {
		logger.Error("Revocation storing failed", "err", err)
		sendAck(proto.Ack_ErrCode_retry, messenger.AckRetryDBError)
		metrics.PSRevocation.Count(labels.WithResult(metrics.ErrDB)).Inc()
		return infra.MetricsErrRevCache(err)
	}
	sendAck(proto.Ack_ErrCode_ok, "")
	metrics.PSRevocation.Count(labels.WithResult(metrics.OkSuccess)).Inc()
	return infra.MetricsResultOk
}
