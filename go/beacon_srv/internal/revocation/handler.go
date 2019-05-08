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

// Package revocation implements a revocation handler for the beacon server.
package revocation

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon/metrics"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

// Store is the store in which to save the revocations.
type Store interface {
	InsertRevocations(ctx context.Context, verifiedRevs ...*path_mgmt.SignedRevInfo) error
}

type handler struct {
	verifier infra.Verifier
	revStore Store
	timeout  time.Duration
}

func NewHandler(revStore Store, verifier infra.Verifier, timeout time.Duration) infra.Handler {
	return &handler{
		verifier: verifier,
		revStore: revStore,
		timeout:  timeout,
	}
}

func (h *handler) Handle(request *infra.Request) *infra.HandlerResult {
	logger := log.FromCtx(request.Context())
	revocation, ok := request.Message.(*path_mgmt.SignedRevInfo)
	if !ok {
		logger.Error("[RevHandler] wrong message type, expected path_mgmt.SignedRevInfo",
			"msg", request.Message, "type", common.TypeOf(request.Message))
		return infra.MetricsErrInternal
	}
	rw, ok := infra.ResponseWriterFromContext(request.Context())
	if !ok {
		logger.Error("[RevHandler] Unable to service request, no ResponseWriter found",
			"msg", request.Message)
		return infra.MetricsErrInternal
	}
	subCtx, cancelF := context.WithTimeout(request.Context(), h.timeout)
	defer cancelF()

	sendAck := messenger.SendAckHelper(subCtx, rw)
	revInfo, err := revocation.VerifiedRevInfo(subCtx, h.verifier)
	if err != nil {
		logger.Warn("[RevHandler] Parsing/Verifying failed",
			"signer", revocation.Sign.Src, "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		return infra.MetricsErrInvalid
	}
	err = h.revStore.InsertRevocations(subCtx, revocation)
	if err != nil {
		logger.Error("[RevHandler] Failed to store", "rev", revInfo, "err", err)
		sendAck(proto.Ack_ErrCode_retry, messenger.AckRetryDBError)
		return metrics.ErrBeaconStore(err)
	}
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk
}
