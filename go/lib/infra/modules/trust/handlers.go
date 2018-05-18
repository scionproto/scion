// Copyright 2018 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
)

// trcReqHandler contains the state of a handler for a specific TRC Request
// message, received via the Messenger's ListenAndServe method.
type trcReqHandler struct {
	request *infra.Request
	store   *Store
	log     log.Logger
	// set to true if this handler is allowed to issue new requests over the
	// network
	recurse bool
}

func (h *trcReqHandler) Handle() {
	trcReq, ok := h.request.Message.(*cert_mgmt.TRCReq)
	if !ok {
		h.log.Error("wrong message type, expected cert_mgmt.TRCReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}

	messenger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		h.log.Warn("Unable to service request, no Messenger found in context.")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	// Only allow network traffic to be sent out if recursion is enabled and
	// CacheOnly is not requested.
	// FIXME(scrye): when protocol support is in, the below needs to select
	// between verified/unverified retrieval based on message content.
	trc, err := h.store.getTRC(h.request.Context(), trcReq.ISD, trcReq.Version,
		h.recurse && !trcReq.CacheOnly, h.request.Peer)
	if err != nil {
		h.log.Error("Unable to retrieve TRC", "err", err)
		return
	}

	// FIXME(scrye): avoid recompressing this for every request
	rawTRC, err := trc.Compress()
	if err != nil {
		h.log.Warn("Unable to compress TRC", "err", err)
		return
	}
	trcMessage := &cert_mgmt.TRC{
		RawTRC: rawTRC,
	}
	if err := messenger.SendTRC(subCtx, trcMessage, h.request.Peer, h.request.ID); err != nil {
		h.log.Error("Messenger API error", "err", err)
	}
}

// chainReqHandler contains the state of a handler for a specific Certificate
// Chain Request message, received via the Messenger's ListenAndServe method.
type chainReqHandler struct {
	request *infra.Request
	store   *Store
	log     log.Logger
	// set to true if this handler is allowed to issue new requests over the
	// network
	recurse bool
}

func (h *chainReqHandler) Handle() {
	chainReq, ok := h.request.Message.(*cert_mgmt.ChainReq)
	if !ok {
		h.log.Error("wrong message type, expected cert_mgmt.ChainReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}

	messenger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		h.log.Warn("Unable to service request, no Messenger found in context.")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	// Only allow network traffic to be sent out if recursion is enabled and
	// CacheOnly is not requested.
	// FIXME(scrye): when protocol support is in, the below needs to select
	// between verified/unverified retrieval based on message content.
	chain, err := h.store.getChain(h.request.Context(), chainReq.IA(), chainReq.Version,
		h.recurse && !chainReq.CacheOnly, h.request.Peer)
	if err != nil {
		h.log.Error("Unable to retrieve Chain", "err", err)
		return
	}

	rawChain, err := chain.Compress()
	if err != nil {
		h.log.Warn("Unable to compress Chain", "err", err)
		return
	}
	chainMessage := &cert_mgmt.Chain{
		RawChain: rawChain,
	}
	err = messenger.SendCertChain(subCtx, chainMessage, h.request.Peer, h.request.ID)
	if err != nil {
		h.log.Error("Messenger API error", "err", err)
	}
}
