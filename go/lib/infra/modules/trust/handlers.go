// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/proto"
)

// trcReqHandler contains the state of a handler for a specific TRC Request
// message, received via the Messenger's ListenAndServe method.
type trcReqHandler struct {
	request *infra.Request
	store   *Store
	// set to true if this handler is allowed to issue new requests over the
	// network
	recurse bool
}

func (h *trcReqHandler) Handle() {
	logger := log.FromCtx(h.request.Context())
	trcReq, ok := h.request.Message.(*cert_mgmt.TRCReq)
	if !ok {
		logger.Error("[TrustStore:trcReqHandler] wrong message type, expected cert_mgmt.TRCReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	logger.Debug("[TrustStore:trcReqHandler] Received request", "trcReq", trcReq,
		"peer", h.request.Peer)
	messenger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Warn("[TrustStore:trcReqHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	var trcObj *trc.TRC
	var err error
	// Only allow network traffic to be sent out if recursion is enabled and
	// CacheOnly is not requested.
	// FIXME(scrye): when protocol support is in, the below needs to select
	// between verified/unverified retrieval based on message content. For now,
	// call getTRC instead of getValidTRC.
	if trcReq.CacheOnly {
		trcObj, err = h.store.trustdb.GetTRCVersion(h.request.Context(), trcReq.ISD, trcReq.Version)
	} else {
		trcObj, err = h.store.getTRC(h.request.Context(), trcReq.ISD, trcReq.Version,
			h.recurse, h.request.Peer, nil)
	}
	if err != nil {
		logger.Error("[TrustStore:trcReqHandler] Unable to retrieve TRC", "err", err)
		return
	}
	var rawTRC common.RawBytes
	if trcObj != nil {
		// FIXME(scrye): avoid recompressing this for every request
		rawTRC, err = trcObj.Compress()
		if err != nil {
			logger.Warn("[TrustStore:trcReqHandler] Unable to compress TRC", "err", err)
			return
		}
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
	// set to true if this handler is allowed to issue new requests over the
	// network
	recurse bool
}

func (h *chainReqHandler) Handle() {
	logger := log.FromCtx(h.request.Context())
	chainReq, ok := h.request.Message.(*cert_mgmt.ChainReq)
	if !ok {
		logger.Error("[TrustStore:chainReqHandler] wrong message type, expected cert_mgmt.ChainReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	logger.Debug("[TrustStore:chainReqHandler] Received request", "chainReq", chainReq,
		"peer", h.request.Peer)
	messenger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Warn("[TrustStore:chainReqHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	var chain *cert.Chain
	var err error
	// Only allow network traffic to be sent out if recursion is enabled and
	// CacheOnly is not requested.
	// FIXME(scrye): when protocol support is in, the below needs to select
	// between verified/unverified retrieval based on message content. For now,
	// call getChain instead of getValidChain.
	if chainReq.CacheOnly {
		chain, err = h.store.trustdb.GetChainVersion(h.request.Context(),
			chainReq.IA(), chainReq.Version)
	} else {
		chain, err = h.store.getChain(h.request.Context(), chainReq.IA(), chainReq.Version,
			h.recurse, h.request.Peer)
	}
	if err != nil {
		logger.Error("[TrustStore:chainReqHandler] Unable to retrieve Chain", "err", err)
		return
	}
	var rawChain common.RawBytes
	if chain != nil {
		rawChain, err = chain.Compress()
		if err != nil {
			logger.Error("[TrustStore:chainReqHandler] Unable to compress Chain", "err", err)
			return
		}
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
}

func (h *trcPushHandler) Handle() {
	logger := log.FromCtx(h.request.Context())
	// FIXME(scrye): In case a TRC update will invalidate the local certificate
	// chain after the gracePeriod, CSes must use this gracePeriod to fetch a
	// new chain from the issuer. If a chain is not obtained within the
	// gracePeriod, manual intervention is required to install a valid chain.
	trcPush, ok := h.request.Message.(*cert_mgmt.TRC)
	if !ok {
		logger.Error("[TrustStore:trcPushHandler] Wrong message type, expected cert_mgmt.TRC",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	logger.Debug("[TrustStore:trcPushHandler] Received push", "trcPush", trcPush,
		"peer", h.request.Peer)
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Warn("[TrustStore:trcPushHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	sendAck := messenger.SendAckHelper(subCtx, msger, h.request.Peer, h.request.ID)
	// FIXME(scrye): Verify that the TRC is valid by using the trust store and
	// known trust topology. Use h.Request.Peer to retrieve missing TRCs.
	trcObj, err := trcPush.TRC()
	if err != nil {
		logger.Error("[TrustStore:trcPushHandler] Unable to extract TRC from TRC push", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return
	}
	if trcObj == nil {
		logger.Warn("[TrustStore:trcPushHandler] Empty chain received")
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return
	}
	n, err := h.store.trustdb.InsertTRC(subCtx, trcObj)
	if err != nil {
		logger.Error("[TrustStore:trcPushHandler] Unable to insert TRC into DB", "err", err)
		sendAck(proto.Ack_ErrCode_retry, messenger.AckRetryDBError)
		return
	}
	if n != 0 {
		logger.Debug("[TrustStore:trcPushHandler] Inserted TRC into DB", "trc", trcObj)
	}
	sendAck(proto.Ack_ErrCode_ok, "")
}

type chainPushHandler struct {
	request *infra.Request
	store   *Store
}

func (h *chainPushHandler) Handle() {
	logger := log.FromCtx(h.request.Context())
	chainPush, ok := h.request.Message.(*cert_mgmt.Chain)
	if !ok {
		logger.Error("[TrustStore:chainPushHandler] Wrong message type, expected cert_mgmt.Chain",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	logger.Debug("[TrustStore:chainPushHandler] Received push", "chainPush", chainPush,
		"peer", h.request.Peer)
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Warn("[TrustStore:chainPushHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	sendAck := messenger.SendAckHelper(subCtx, msger, h.request.Peer, h.request.ID)
	// FIXME(scrye): Verify that the chain is valid by using the trust store.
	chain, err := chainPush.Chain()
	if err != nil {
		logger.Error("[TrustStore:chainPushHandler] Unable to extract chain from chain push",
			"err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return
	}
	if chain == nil {
		logger.Warn("[TrustStore:chainPushHandler] Empty chain received")
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return
	}
	n, err := h.store.trustdb.InsertChain(subCtx, chain)
	if err != nil {
		logger.Error("[TrustStore:chainPushHandler] Unable to insert chain into DB", "err", err)
		sendAck(proto.Ack_ErrCode_retry, messenger.AckRetryDBError)
		return
	}
	if n != 0 {
		logger.Debug("[TrustStore:chainPushHandler] Inserted chain into DB", "chain", chain)
	}
	sendAck(proto.Ack_ErrCode_ok, "")
}
