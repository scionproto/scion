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
		h.log.Error("[TrustStore:trcReqHandler] wrong message type, expected cert_mgmt.TRCReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	logger := h.log.New("trcReq", trcReq, "peer", h.request.Peer)
	logger.Debug("[TrustStore:trcReqHandler] Received request")
	messenger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Warn("[TrustStore:trcReqHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	// Only allow network traffic to be sent out if recursion is enabled and
	// CacheOnly is not requested.
	// FIXME(scrye): when protocol support is in, the below needs to select
	// between verified/unverified retrieval based on message content. For now,
	// call getTRC instead of getValidTRC.
	trcObj, err := h.store.getTRC(h.request.Context(), trcReq.ISD, trcReq.Version,
		h.recurse && !trcReq.CacheOnly, h.request.Peer)
	if err != nil {
		logger.Error("[TrustStore:trcReqHandler] Unable to retrieve TRC", "err", err)
		return
	}
	// FIXME(scrye): avoid recompressing this for every request
	rawTRC, err := trcObj.Compress()
	if err != nil {
		logger.Warn("[TrustStore:trcReqHandler] Unable to compress TRC", "err", err)
		return
	}
	trcMessage := &cert_mgmt.TRC{
		RawTRC: rawTRC,
	}
	if err := messenger.SendTRC(subCtx, trcMessage, h.request.Peer, h.request.ID); err != nil {
		logger.Error("[TrustStore:trcReqHandler] Messenger error", "err", err)
		return
	}
	logger.Debug("[TrustStore:trcReqHandler] Replied with TRC",
		"trc", trcObj, "peer", h.request.Peer)
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
		h.log.Error("[TrustStore:chainReqHandler] wrong message type, expected cert_mgmt.ChainReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	logger := h.log.New("chainReq", chainReq, "peer", h.request.Peer)
	logger.Debug("[TrustStore:chainReqHandler] Received request")
	messenger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Warn("[TrustStore:chainReqHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	// Only allow network traffic to be sent out if recursion is enabled and
	// CacheOnly is not requested.
	// FIXME(scrye): when protocol support is in, the below needs to select
	// between verified/unverified retrieval based on message content. For now,
	// call getChain instead of getValidChain.
	chain, err := h.store.getChain(h.request.Context(), chainReq.IA(), chainReq.Version,
		h.recurse && !chainReq.CacheOnly, h.request.Peer)
	if err != nil {
		logger.Error("[TrustStore:chainReqHandler] Unable to retrieve Chain", "err", err)
		return
	}

	rawChain, err := chain.Compress()
	if err != nil {
		logger.Error("[TrustStore:chainReqHandler] Unable to compress Chain", "err", err)
		return
	}
	chainMessage := &cert_mgmt.Chain{
		RawChain: rawChain,
	}
	err = messenger.SendCertChain(subCtx, chainMessage, h.request.Peer, h.request.ID)
	if err != nil {
		logger.Error("[TrustStore:chainReqHandler] Messenger API error", "err", err)
		return
	}
	logger.Debug("[TrustStore:chainReqHandler] Replied with chain",
		"chain", chain, "peer", h.request.Peer)
}

type trcPushHandler struct {
	request *infra.Request
	store   *Store
	log     log.Logger
}

func (h *trcPushHandler) Handle() {
	// FIXME(scrye): In case a TRC update will invalidate the local certificate
	// chain after the gracePeriod, CSes must use this gracePeriod to fetch a
	// new chain from the issuer. If a chain is not obtained within the
	// gracePeriod, manual intervention is required to install a valid chain.
	trcPush, ok := h.request.Message.(*cert_mgmt.TRC)
	if !ok {
		h.log.Error("[TrustStore:trcPushHandler] Wrong message type, expected cert_mgmt.TRC",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	logger := h.log.New("trcPush", trcPush, "peer", h.request.Peer)
	logger.Debug("[TrustStore:trcPushHandler] Received push")
	// FIXME(scrye): Verify that the TRC is valid by using the trust store and
	// known trust topology. Use h.Request.Peer to retrieve missing TRCs.
	trcObj, err := trcPush.TRC()
	if err != nil {
		logger.Error("[TrustStore:trcPushHandler] Unable to extract TRC from TRC push", "err", err)
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	n, err := h.store.trustdb.InsertTRCCtx(subCtx, trcObj)
	if err != nil {
		logger.Error("[TrustStore:trcPushHandler] Unable to insert TRC into DB", "err", err)
		return
	}
	if n != 0 {
		logger.Debug("[TrustStore:trcPushHandler] Inserted TRC into DB", "trc", trcObj)
	}
}

type chainPushHandler struct {
	request *infra.Request
	store   *Store
	log     log.Logger
}

func (h *chainPushHandler) Handle() {
	chainPush, ok := h.request.Message.(*cert_mgmt.Chain)
	if !ok {
		h.log.Error("[TrustStore:chainPushHandler] Wrong message type, expected cert_mgmt.Chain",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	logger := h.log.New("chainPush", chainPush, "peer", h.request.Peer)
	logger.Debug("[TrustStore:chainPushHandler] Received push")
	// FIXME(scrye): Verify that the chain is valid by using the trust store.
	chain, err := chainPush.Chain()
	if err != nil {
		logger.Error("[TrustStore:chainPushHandler] Unable to extract chain from chain push",
			"err", err)
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	n, err := h.store.trustdb.InsertChainCtx(subCtx, chain)
	if err != nil {
		logger.Error("[TrustStore:chainPushHandler] Unable to insert chain into DB", "err", err)
		return
	}
	if n != 0 {
		logger.Debug("[TrustStore:chainPushHandler] Inserted chain into DB", "chain", chain)
	}
}
