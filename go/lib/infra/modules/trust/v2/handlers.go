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
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
)

// HandlerTimeout is the lifetime of the handlers.
const HandlerTimeout = 3 * time.Second

// chainReqHandler contains the state of a handler for a specific Certificate
// Chain Request message, received via the Messenger's ListenAndServe method.
type chainReqHandler struct {
	request  *infra.Request
	provider CryptoProvider
}

func (h *chainReqHandler) Handle() *infra.HandlerResult {
	if h.request == nil {
		log.Error("[TrustStore:chainReqHandler] received nil request")
		return infra.MetricsErrInternal
	}
	logger := log.FromCtx(h.request.Context())
	chainReq, ok := h.request.Message.(*cert_mgmt.ChainReq)
	if !ok {
		logger.Error("[TrustStore:chainReqHandler] wrong message type, expected cert_mgmt.ChainReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	logger.Debug("[TrustStore:chainReqHandler] Received request", "chainReq", chainReq,
		"peer", h.request.Peer)
	rw, ok := infra.ResponseWriterFromContext(h.request.Context())
	if !ok {
		logger.Warn("[TrustStore:chainReqHandler] Unable to service request, no Messenger found")
		return infra.MetricsErrInternal
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	opts := infra.ChainOpts{
		TrustStoreOpts: infra.TrustStoreOpts{
			LocalOnly: chainReq.CacheOnly,
		},
		AllowInactiveTRC: true,
	}
	raw, err := h.provider.GetRawChain(h.request.Context(), chainReq.IA(), chainReq.Version,
		opts, h.request.Peer)
	if err != nil {
		// FIXME(roosd): We should send a negative response.
		logger.Error("[TrustStore:chainReqHandler] Unable to retrieve chain", "err", err)
		return infra.MetricsErrTrustStore(err)
	}
	chainMessage := &cert_mgmt.Chain{
		RawChain: raw,
	}
	if err = rw.SendCertChainReply(subCtx, chainMessage); err != nil {
		logger.Error("[TrustStore:chainReqHandler] Messenger API error", "err", err)
		return infra.MetricsErrMsger(err)
	}
	logger.Debug("[TrustStore:chainReqHandler] Replied with chain",
		"ia", chainReq.IA(), "version", chainReq.Version, "peer", h.request.Peer)
	return infra.MetricsResultOk
}
