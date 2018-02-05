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

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
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

	v := h.request.Context().Value(infra.MessengerContextKey)
	if v == nil {
		h.log.Warn("Unable to service request, no Messenger interface found")
		return
	}
	messenger, ok := v.(infra.Messenger)
	if !ok {
		h.log.Warn("Unable to service request, bad Messenger interface found",
			"value", v, "type", common.TypeOf(v))
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	// FIXME(scrye): If this is a core CS or non-core CS, additional logic is
	// needed here to choose a hint/source for the trcRequest:
	//   - if local process is non-core CS, it should select a Core-CS in the local ISD
	//   - if local process is core CS, it should select a CS in the target AS
	request := trcRequest{
		isd:      uint16(trcReq.ISD),
		version:  trcReq.Version,
		hint:     nil, // FIXME: Fix this for CS servers
		verifier: nil, // FIXME: This needs additional logic to select the correct verifier
	}
	trc, err := h.store.getTRC(h.request.Context(), request, h.recurse, h.request.Peer)
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
	if err := messenger.SendTRC(subCtx, trcMessage, h.request.Peer); err != nil {
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

	v := h.request.Context().Value(infra.MessengerContextKey)
	if v == nil {
		h.log.Warn("Unable to service request, no Messenger interface found")
		return
	}
	messenger, ok := v.(infra.Messenger)
	if !ok {
		h.log.Warn("Unable to service request, bad Messenger interface found",
			"value", v, "type", common.TypeOf(v))
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()

	// FIXME(scrye): Same observations as in trcReqHandler.Handle
	request := chainRequest{
		ia:       *chainReq.IA(),
		version:  chainReq.Version,
		hint:     nil, // FIXME
		verifier: nil, // FIXME
	}
	chain, err := h.store.getChain(h.request.Context(), request, h.recurse, h.request.Peer)
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
	if err := messenger.SendCertChain(subCtx, chainMessage, h.request.Peer); err != nil {
		h.log.Error("Messenger API error", "err", err)
	}
}

// trcPushHandler contains the state of a handler for a specific TRC message,
// received via the Messenger's ListenAndServe method.
type trcPushHandler struct {
	request *infra.Request
	store   *Store
	log     log.Logger
}

func (h *trcPushHandler) Handle() {
	trcUpdate, ok := h.request.Message.(*cert_mgmt.TRC)
	if !ok {
		h.log.Error("wrong message type, expected cert_mgmt.TRC",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	trcObj, err := trcUpdate.TRC()
	if err != nil {
		h.log.Error("Unable to parse TRC in unsolicited update", "peer", h.request.Peer, "err", err)
		return
	}

	result := h.store.peekTRCVerify(h.request.Context(), trcObj)
	switch result {
	case resultSuccessExists:
		h.log.Info("Received unsolicited TRC update from node, but already have object",
			"ISD", trcObj.ISD, "version", trcObj.Version, "sender", h.request.Peer)
	case resultSuccessVerified:
		err := h.store.trustdb.InsertTRCCtx(h.request.Context(), trcObj.ISD, trcObj.Version, trcObj)
		if err != nil {
			h.log.Error("Unable to insert TRC in trust database",
				"ISD", trcObj.ISD, "version", trcObj.Version, "sender", h.request.Peer, "err", err)
		}
	case resultFailure:
		h.log.Error("Unable to verify TRC in unsolicited update",
			"ISD", trcObj.ISD, "version", trcObj.Version, "sender", h.request.Peer)
	}
}

// chainPushHandler contains the state of a handler for a specific Certificate
// Chain message, received via the Messenger's ListenAndServe method.
type chainPushHandler struct {
	request *infra.Request
	store   *Store
	log     log.Logger
}

func (h *chainPushHandler) Handle() {
	chainUpdate, ok := h.request.Message.(*cert_mgmt.Chain)
	if !ok {
		h.log.Error("wrong message type, expected cert_mgmt.Chain",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	chain, err := chainUpdate.Chain()
	if err != nil {
		h.log.Error("Unable to parse Chain in unsolicited update", "peer", h.request.Peer,
			"err", err)
		return
	}

	result := h.store.peekChainVerify(h.request.Context(), chain)
	switch result {
	case resultSuccessExists:
		h.log.Info("Received unsolicited TRC update from node, but already have object",
			"AS", chain.Leaf.Subject, "version", chain.Leaf.Version, "sender", h.request.Peer)
	case resultSuccessVerified:
		err := h.store.trustdb.InsertChainCtx(h.request.Context(), *chain.Leaf.Subject,
			chain.Leaf.Version, chain)
		if err != nil {
			h.log.Error("Unable to insert TRC in trust database",
				"AS", chain.Leaf.Subject, "version", chain.Leaf.Version, "sender", h.request.Peer,
				"err", err)
		}
	case resultFailure:
		h.log.Error("Unable to verify TRC in unsolicited update",
			"AS", chain.Leaf.Subject, "version", chain.Leaf.Version, "sender", h.request.Peer)
	}
}
