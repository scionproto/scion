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

package trust

import (
	"context"
	"errors"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/proto"
)

type chainPushHandler struct {
	request  *infra.Request
	provider CryptoProvider
	inserter Inserter
}

func (h *chainPushHandler) Handle() *infra.HandlerResult {
	if h.request == nil {
		log.Error("[TrustStore:chainPushHandler] Request is nil")
		return infra.MetricsErrInternal
	}
	logger := log.FromCtx(h.request.Context())
	if h.request.Message == nil {
		logger.Error("[TrustStore:chainPushHandler] Request message is nil")
		return infra.MetricsErrInternal
	}
	chainPush, ok := h.request.Message.(*cert_mgmt.Chain)
	if !ok {
		logger.Error("[TrustStore:chainPushHandler] Wrong message type, expected cert_mgmt.Chain",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	logger.Trace("[TrustStore:chainPushHandler] Received push", "chainPush", chainPush,
		"peer", h.request.Peer)
	rw, ok := infra.ResponseWriterFromContext(h.request.Context())
	if !ok {
		logger.Warn("[TrustStore:chainPushHandler] Unable to service request, no Messenger found")
		return infra.MetricsErrInternal
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), messenger.DefaultHandlerTimeout)
	defer cancelF()
	sendAck := messenger.SendAckHelper(subCtx, rw)

	dec, err := decoded.DecodeChain(chainPush.RawChain)
	if err != nil {
		logger.Error("[TrustStore:chainPushHandler] Unable to parse chain from push", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid
	}
	err = h.inserter.InsertChain(h.request.Context(), dec, newTRCGetter(h.provider, h.request.Peer))
	switch {
	case err == nil:
		sendAck(proto.Ack_ErrCode_ok, "")
		return infra.MetricsResultOk
	case errors.Is(err, ErrContentMismatch):
		logger.Error("[TrustStore:chainPushHandler] Certificate already exists with different hash",
			"err", err, "chain", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		return infra.MetricsErrInvalid
	case errors.Is(err, ErrValidation), errors.Is(err, ErrVerification):
		logger.Error("[TrustStore:chainPushHandler] Unable to verify certificate chain",
			"err", err, "chain", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		return infra.MetricsErrInvalid
	default:
		logger.Error("[TrustStore:chainPushHandler] Error inserting certificate chain",
			"err", err, "chain", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRetryDBError)
		return infra.MetricsErrInternal
	}
}

func newTRCGetter(provider CryptoProvider, peer net.Addr) func(context.Context,
	addr.ISD, scrypto.Version) (*trc.TRC, error) {

	return func(ctx context.Context, isd addr.ISD, version scrypto.Version) (*trc.TRC, error) {
		opts := infra.TRCOpts{
			TrustStoreOpts: infra.TrustStoreOpts{
				Server: peer,
			},
			AllowInactive: true,
		}
		return provider.GetTRC(ctx, isd, version, opts)
	}
}
