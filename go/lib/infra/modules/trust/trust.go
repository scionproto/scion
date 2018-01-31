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

// Package trust defines type Store, a unified interface for TRC and Certificate
// retrieval.
package trust

import (
	"context"
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

const (
	// Maximum number of requests waiting to be picked up by the trust server.
	// If the maximum is reached and a goroutine attempts to register a new
	// request, it will receive an error.
	MaxPendingRequests = 64
	// Handler lifetime
	HandlerTimeout = 3 * time.Second
)

// Store manages requests for TRC and Certificate Chain objects.
//
// Certificate requests from local server logic are handled by GetCertificate,
// while requests from other services can be handled via XxxReqHandler methods.
//
// By default, a Store object can only return objects that are already present
// in the database. To allow a Store to use the SCION network to retrieve
// objects from other infrastructure services, method StartResolvers must be
// called with an operational infra.Messenger object.
//
// Currently Store is backed by a sqlite3 database in package
// go/lib/infra/components/trust/trustdb.
type Store struct {
	trustdb *trustdb.DB
	// channel to send TRC requests from client goroutines to the backend
	// resolver
	trcRequests chan requestI
	// channel to send Certificate Chain requests from client goroutines to the
	// backend resolver
	chainRequests chan requestI
	// set to true if the trust store should create chain and TRC remote
	// request handlers with recursion enabled (i.e., request forwarding)
	recurse bool
	// local AS
	ia  addr.ISD_AS
	log log.Logger

	// Used to serialize access to Close
	closeMutex sync.Mutex
	// Set to true once Closed successfully completes
	closedFlag bool

	// Used to serialize access to StartResolvers
	startMutex sync.Mutex
	// Set to true once StartResolvers successfully completes
	startedFlag bool
}

// NewStore initializes a TRC cache/resolver backed by SQLite3 database at
// path. Parameter local must specify the AS in which the trust store resides
// (which is used during request forwarding decisions).
func NewStore(db *trustdb.DB, local addr.ISD_AS, logger log.Logger) (*Store, error) {
	return &Store{
		trustdb:       db,
		trcRequests:   make(chan requestI, MaxPendingRequests),
		chainRequests: make(chan requestI, MaxPendingRequests),
		ia:            local,
		log:           logger,
	}, nil
}

// StartResolvers launches goroutines for handling TRC and Cert requests that
// are not available in the local database. Outgoing (network) requests are
// throttled s.t. at most one request for each address and version is sent
// every MinimumDelta duration. Received objects are verified prior to
// insertion into the backing database. Parameter recurse states whether
// goroutines that service requests coming over the network for objects that
// are not available locally are allowed to send out new requests over the
// network (i.e., request forwarding).
func (store *Store) StartResolvers(messenger infra.Messenger, recurse bool) error {
	store.startMutex.Lock()
	defer store.startMutex.Unlock()
	store.closeMutex.Lock()
	defer store.closeMutex.Unlock()
	if store.closedFlag == true {
		// Prohibit resolver start after Close has been called
		return common.NewBasicError("start after close", nil)
	}
	if store.startedFlag == true {
		// Prohibit double starts
		return common.NewBasicError("double start", nil)
	}
	store.recurse = recurse
	store.startedFlag = true
	trcResolver := &resolver{
		msger:           messenger,
		trustdb:         store.trustdb,
		requests:        store.trcRequests,
		completionChans: make(map[string]chan chan<- error),
		log:             store.log.New("goroutine", "trcResolver"),
	}
	go trcResolver.Run()
	chainResolver := &resolver{
		msger:           messenger,
		trustdb:         store.trustdb,
		requests:        store.chainRequests,
		completionChans: make(map[string]chan chan<- error),
		log:             store.log.New("goroutine", "chainResolver"),
	}
	go chainResolver.Run()
	return nil
}

// getTRC attempts to grab the TRC from the database; if the TRC is not found,
// it follows up with a network request (if allowed).  Parameter request
// specifies whether this function is allowed to create new network requests.
// Parameter requester contains the node that caused the function to be called,
// or nil if the function was called due to a local feature.
func (store *Store) getTRC(ctx context.Context, req trcRequest, recurse bool,
	requester net.Addr) (*trc.TRC, error) {
	for {
		// Attempt to get the TRC from the local cache
		if trc, err := store.trustdb.GetTRCVersionCtx(ctx, req.isd, req.version); err != nil {
			return nil, err
		} else if trc != nil {
			return trc, nil
		}
		if !store.startedFlag {
			return nil, common.NewBasicError("TRC not found in DB, and network access disabled",
				nil)
		}
		if requester != nil {
			// If we cannot extract the AS of the requester or it doesn't match
			// with our AS, never forward the request.
			saddr, ok := requester.(*snet.Addr)
			if !ok || !store.ia.Eq(saddr.IA) {
				return nil, common.NewBasicError("TRC not found in DB, and recursion not "+
					"allowed for clients outside AS", nil, "client", saddr)
			}
		}
		if recurse == false {
			return nil, common.NewBasicError("TRC not found in DB, and recursion disabled", nil)
		}
		// TRC not found, forward a request to the background TRC resolver
		if err := store.issueTRCRequest(ctx, req); err != nil {
			return nil, err
		}
	}
}

// issueTRCRequest requests a TRC from the trust store backend.
func (store *Store) issueTRCRequest(ctx context.Context, req trcRequest) error {
	select {
	case store.trcRequests <- req:
	default:
		return common.NewBasicError("Unable to request TRC, queue full",
			nil, "isd", req.isd, "version", req.version)
	}
	// Block waiting for request to be finalized
	select {
	case err := <-req.errChan:
		return err
	case <-ctx.Done():
		// Context expired while waiting
		return common.NewBasicError("Context canceled while waiting for TRC",
			nil, "isd", req.isd, "version", req.version)
	}
}

// getChain attempts to grab the Certificate Chain from the database; if the
// Chain is not found, it follows up with a network request (if allowed).
// Parameter request specifies whether this function is allowed to create new
// network requests. Parameter requester contains the node that caused the
// function to be called, or nil if the function was called due to a local
// feature.
func (store *Store) getChain(ctx context.Context, req chainRequest,
	recurse bool, requester net.Addr) (*cert.Chain, error) {
	for {
		// Attempt to get the Chain from the local cache
		if chain, err := store.trustdb.GetChainVersionCtx(ctx, req.ia, req.version); err != nil {
			return nil, err
		} else if chain != nil {
			return chain, nil
		}
		if !store.startedFlag {
			return nil, common.NewBasicError("Chain not found in DB, and network access disabled",
				nil)
		}
		if requester != nil {
			// If we cannot extract the AS of the requester or it doesn't match with our AS,
			// never forward the request.
			saddr, ok := requester.(*snet.Addr)
			if !ok || !store.ia.Eq(saddr.IA) {
				return nil, common.NewBasicError("Chain not found in DB, and recursion not "+
					"allowed for clients outside AS", nil, "client", saddr)
			}
		}
		if recurse == false {
			return nil, common.NewBasicError("Chain not found in DB, and recursion disabled", nil)
		}
		// Chain not found, forward the request to the background Chain resolver
		if err := store.issueChainRequest(ctx, req); err != nil {
			return nil, err
		}
	}
}

// issueChainRequest requests a Chain from the trust store backend.
func (store *Store) issueChainRequest(ctx context.Context, req chainRequest) error {
	select {
	case store.chainRequests <- req:
	default:
		return common.NewBasicError("Unable to request Chain, queue full",
			nil, "ia", req.ia, "version", req.version)
	}
	// Block waiting for request to be finalized
	select {
	case err := <-req.errChan:
		return err
	case <-ctx.Done():
		// Context expired while waiting
		return common.NewBasicError("Context canceled while waiting for Chain",
			nil, "ia", req.ia, "version", req.version)
	}
}

// NewTRCReqHandler runs a handler for TRC request data coming from peer. This
// should only be used when servicing requests coming from remote nodes.
func (store *Store) TRCReqHandler(ctx context.Context, data, _ proto.Cerealizable, peer net.Addr) {
	trcReq, ok := data.(*cert_mgmt.TRCReq)
	if !ok {
		store.log.Error("wrong message type, expected cert_mgmt.TRCReq",
			"msg", data, "type", common.TypeOf(data))
		return
	}
	reqObject := &trcReqHandler{
		data:  trcReq,
		peer:  peer,
		cache: store,
		log:   store.log,
	}
	reqObject.Handle(ctx)
}

// NewChainReqHandler initializes a handler for TRC request data coming from
// peer. This should only be used when servicing requests coming from remote
// nodes.
func (store *Store) ChainReqHandler(ctx context.Context, data, _ proto.Cerealizable,
	peer net.Addr) {
	chainReq, ok := data.(*cert_mgmt.ChainReq)
	if !ok {
		store.log.Error("wrong message type, expected cert_mgmt.ChainReq",
			"msg", data, "type", common.TypeOf(data))
	}
	reqObject := &chainReqHandler{
		data:  chainReq,
		peer:  peer,
		cache: store,
		log:   store.log,
	}
	reqObject.Handle(ctx)
}

func (store *Store) GetCertificate(ctx context.Context, trail []Descriptor,
	hint net.Addr) (*cert.Certificate, error) {
	verifierObj, err := store.getCertificate(ctx, trail, hint)
	if err != nil {
		return nil, err
	}
	// If we get a panic on this type assertion, it means the trust trail was
	// not valid (e.g., the trail started with a TRC descriptor instead of a
	// Chain descriptor.
	chain := verifierObj.(*cert.Chain)
	return chain.Leaf, err
}

// getCertificate recursively follows trail to create a fully verified trust
// chain leading up to trail[0].  Given a trail composed of:
//   [Cert0, TRC0, TRC1, TRC2]
// getCertificate first tries to see if Cert0 is in trustdb. If it's not, it
// recursively calls getCertificate on new trail:
//   [TRC0, TRC1, TRC2]
// and eventually:
//   [TRC1, TRC2]
// Suppose TRC2 is in the database. The function returns (TRC2, nil). The
// caller now has access to TRC2, and needs to obtain TRC1. It issues a call to
// the backend passing TRC2 as a verifier. Once it gets TRC1, it returns it.
//
// TRC1 is then used to download TRC0, and finally TRC0 is used to download
// Cert0, and the recursion finishes.
func (store *Store) getCertificate(ctx context.Context, trail []Descriptor,
	hint net.Addr) (interface{}, error) {
	// Attempt to read the object described by the current trust descriptor from
	// the database.
	trustObject, err := store.queryByDescriptor(ctx, trail[0])
	if err != nil {
		return nil, err
	}
	if trustObject != nil {
		return trustObject, nil
	}

	// The trust object needed to perform verification is not in trustdb;
	// advance the trail and recursively try to get the next object.
	nextObj, err := store.getCertificate(ctx, trail[1:], hint)
	if err != nil {
		return nil, err
	}
	// Getting a panic on this trust assertion means the trust trail was
	// not valid (e.g., multiple chains  were present, but this
	// functionality is not supported yet).
	nextTRC := nextObj.(*trc.TRC)

	// We have the next trust object, so we can issue a request to the backend
	// for the current trust object by passing it as the verifier.
	return store.fetchByDescriptor(ctx, trail[0], hint, nextTRC)
}

func (store *Store) queryByDescriptor(ctx context.Context, desc Descriptor) (interface{}, error) {
	switch desc.Type {
	case ChainDescriptor:
		chain, err := store.trustdb.GetChainVersionCtx(ctx, desc.IA, desc.Version)
		if err != nil {
			return nil, common.NewBasicError("Query GetChainVersionCtx to trustdb failed", err)
		}
		if chain != nil {
			// We have the needed chain already, we can return
			return chain.Leaf, nil
		}
	case TRCDescriptor:
		trcObj, err := store.trustdb.GetTRCVersionCtx(ctx, uint16(desc.IA.I), desc.Version)
		if err != nil {
			return nil, common.NewBasicError("Query GetTRCVersionCtx to trustdb failed", err)
		}
		if trcObj != nil {
			// We found the root of trust in the database, we can now go
			// back and download/verify missing TRCs and certificate chains
			// starting from it.
			return trcObj, nil
		}
	default:
		return nil, common.NewBasicError("Unknown descriptor type", nil, "type", desc.Type)
	}
	// object described by desc not found
	return nil, nil
}

func (store *Store) fetchByDescriptor(ctx context.Context, desc Descriptor, hint net.Addr,
	verifier *trc.TRC) (interface{}, error) {
	switch desc.Type {
	case ChainDescriptor:
		request := chainRequest{
			ia:       desc.IA,
			version:  desc.Version,
			verifier: verifier,
			hint:     hint,
			errChan:  make(chan error, 1),
		}
		return store.getChain(ctx, request, true, nil)
	case TRCDescriptor:
		request := trcRequest{
			isd:      uint16(desc.IA.I),
			version:  desc.Version,
			verifier: verifier,
			hint:     hint,
			errChan:  make(chan error, 1),
		}
		return store.getTRC(ctx, request, true, nil)
	default:
		return nil, common.NewBasicError("Unknown descriptor type", nil, "type", desc.Type)
	}
}

// Close shuts down the background TRC and Chain resolvers.
func (store *Store) Close() error {
	store.closeMutex.Lock()
	defer store.closeMutex.Unlock()
	if store.closedFlag == false {
		store.closedFlag = true
		close(store.trcRequests)
		close(store.chainRequests)
		return nil
	}
	return common.NewBasicError("double close", nil)
}

// trcReqHandler contains the handler state for an external request that
// arrived via Store.TRCReqHandler.
type trcReqHandler struct {
	data  *cert_mgmt.TRCReq
	cache *Store
	peer  net.Addr
	log   log.Logger
	// set to true if this handler is allowed to issue new requests over the
	// network
	recurse bool
}

func (h *trcReqHandler) Handle(ctx context.Context) {
	v := ctx.Value(infra.MessengerContextKey)
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
	subCtx, cancelF := context.WithTimeout(ctx, HandlerTimeout)
	defer cancelF()

	request := trcRequest{
		isd:     uint16(h.data.ISD),
		version: h.data.Version,
	}
	trc, err := h.cache.getTRC(ctx, request, h.recurse, h.peer)
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
	if err := messenger.SendTRC(subCtx, trcMessage, h.peer); err != nil {
		h.log.Error("Messenger API error", "err", err)
	}
}

// chainReqHandler contains the handler state for an external request that
// arrived via Store.ChainReqHandler.
type chainReqHandler struct {
	data  *cert_mgmt.ChainReq
	cache *Store
	peer  net.Addr
	log   log.Logger
	// set to true if this handler is allowed to issue new requests over the
	// network
	recurse bool
}

func (h *chainReqHandler) Handle(ctx context.Context) {
	v := ctx.Value(infra.MessengerContextKey)
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
	subCtx, cancelF := context.WithTimeout(ctx, HandlerTimeout)
	defer cancelF()

	request := chainRequest{
		ia:      *h.data.IA(),
		version: h.data.Version,
	}
	chain, err := h.cache.getChain(ctx, request, h.recurse, h.peer)
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
	if err := messenger.SendCertChain(subCtx, chainMessage, h.peer); err != nil {
		h.log.Error("Messenger API error", "err", err)
	}
}

type Descriptor struct {
	Version uint64
	IA      addr.ISD_AS
	Type    DescriptorType
}

type DescriptorType uint64

const (
	ChainDescriptor DescriptorType = iota
	TRCDescriptor
)
