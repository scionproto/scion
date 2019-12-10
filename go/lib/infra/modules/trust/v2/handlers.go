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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

const (
	// AckNotFound is sent as the error description if the crypto material is
	// not found.
	AckNotFound string = "not found"
)

// trcReqHandler contains the state of a handler for a specific TRC Request
// message, received via the Messenger's ListenAndServe method.
type trcReqHandler struct {
	request  *infra.Request
	provider CryptoProvider
}

func (h *trcReqHandler) Handle() *infra.HandlerResult {
	if h.request == nil {
		log.Error("[TrustStore:trcReqHandler] received nil request")
		return infra.MetricsErrInternal
	}
	logger := log.FromCtx(h.request.Context())
	trcReq, ok := h.request.Message.(*cert_mgmt.TRCReq)
	if !ok {
		logger.Error("[TrustStore:trcReqHandler] wrong message type, expected cert_mgmt.TRCReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	logger.Debug("[TrustStore:trcReqHandler] Received request", "trcReq", trcReq,
		"peer", h.request.Peer)
	rw, ok := infra.ResponseWriterFromContext(h.request.Context())
	if !ok {
		logger.Error("[TrustStore:trcReqHandler] Unable to service request," +
			" no ResponseWriter found")
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(h.request.Context(), rw)
	opts := infra.TRCOpts{
		TrustStoreOpts: infra.TrustStoreOpts{
			LocalOnly: trcReq.CacheOnly,
		},
		AllowInactive: true,
	}
	raw, err := h.provider.GetRawTRC(h.request.Context(), trcReq.ISD, trcReq.Version,
		opts, h.request.Peer)
	if err != nil {
		logger.Error("[TrustStore:trcReqHandler] Unable to retrieve TRC", "err", err)
		sendAck(proto.Ack_ErrCode_reject, AckNotFound)
		return infra.MetricsErrTrustStore(err)
	}
	trcMessage := &cert_mgmt.TRC{
		RawTRC: raw,
	}
	if err := rw.SendTRCReply(h.request.Context(), trcMessage); err != nil {
		logger.Error("[TrustStore:trcReqHandler] Messenger error", "err", err)
		return infra.MetricsErrMsger(err)
	}
	logger.Debug("[TrustStore:trcReqHandler] Replied with TRC", "isd", trcReq.ISD,
		"version", trcReq.Version, "peer", h.request.Peer)
	return infra.MetricsResultOk
}
