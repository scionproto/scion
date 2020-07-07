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

	"github.com/scionproto/scion/go/cs/metrics"
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

// NewHandler returns an infra.Handler for revocation.
func NewHandler(revStore Store, verifier infra.Verifier, timeout time.Duration) infra.Handler {
	return &handler{
		verifier: verifier,
		revStore: revStore,
		timeout:  timeout,
	}
}

// FIXME(karampok): add support for revocation received over SCMP
// https://github.com/scionproto/scion/issues/3166.

// Handle handles receiving revocations.
func (h *handler) Handle(request *infra.Request) *infra.HandlerResult {
	logger := log.FromCtx(request.Context())
	labels := metrics.RevocationLabels{Method: metrics.RevFromCtrl, Result: metrics.ErrProcess}
	revocation, ok := request.Message.(*path_mgmt.SignedRevInfo)
	if !ok {
		logger.Error("[RevHandler] wrong message type, expected path_mgmt.SignedRevInfo",
			"msg", request.Message, "type", common.TypeOf(request.Message))
		metrics.Revocation.Received(labels).Inc()
		return infra.MetricsErrInternal
	}
	rw, ok := infra.ResponseWriterFromContext(request.Context())
	if !ok {
		logger.Error("[RevHandler] Unable to service request, no ResponseWriter found",
			"msg", request.Message)
		metrics.Revocation.Received(labels).Inc()
		return infra.MetricsErrInternal
	}
	subCtx, cancelF := context.WithTimeout(request.Context(), h.timeout)
	defer cancelF()

	sendAck := messenger.SendAckHelper(subCtx, rw)
	revInfo, err := revocation.RevInfo()
	if err != nil {
		logger.Info("[RevHandler] Parsing/Verifying failed",
			"signer", revocation.Sign.Src, "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		metrics.Revocation.Received(labels).Inc()
		return infra.MetricsErrInvalid
	}

	if err = h.revStore.InsertRevocations(subCtx, revocation); err != nil {
		logger.Error("[RevHandler] Failed to store", "rev", revInfo, "err", err)
		sendAck(proto.Ack_ErrCode_retry, messenger.AckRetryDBError)
		metrics.Revocation.Received(labels).Inc()
		return ErrBeaconStore(err)

	}
	sendAck(proto.Ack_ErrCode_ok, "")
	labels.Result = metrics.Success
	metrics.Revocation.Received(labels).Inc()
	return infra.MetricsResultOk
}
