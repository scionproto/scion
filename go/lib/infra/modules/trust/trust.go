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
	"fmt"
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
	"github.com/scionproto/scion/go/proto"
)

const (
	// Maximum number of requests waiting to be picked up by the trust server.
	// If the maximum is reached and a goroutine attempts to register a new
	// request, it will receive an error.
	MaxPendingRequests = 64
)

// Store manages requests for TRC and Certificate Chain objects.
//
// Certificate requests from local server logic are handled by GetCertificate,
// while requests from other services can be handled via NewXxxHandler methods.
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
	// channel to send TRC requests from client goroutines to the backend resolver
	trcRequests chan trcRequest
	// eventMap for client goroutines to block while waiting for a TRC
	trcEvents *eventMap
	// channel to send Certificate Chain requests from client goroutines to the backend resolver
	chainRequests chan chainRequest
	// eventMap for client goroutines to block while waiting for a Certificate Chain
	chainEvents *eventMap
	log         log.Logger

	// Used to serialize access to Close
	closeMutex sync.Mutex
	// Set to true once Closed successfully completes
	closedFlag bool

	// Set to true once StartResolvers successfully completes
	startedFlag bool
	// Used to serialize access to StartResolvers
	startMutex sync.Mutex
}

// NewStore initializes a TRC cache/resolver backed by SQLite3 database at
// path.
func NewStore(path string, logger log.Logger) (*Store, error) {
	db, err := trustdb.New(path)
	if err != nil {
		return nil, common.NewBasicError("Unable to initialize trustdb", err)
	}
	return &Store{
		trustdb:       db,
		trcRequests:   make(chan trcRequest, MaxPendingRequests),
		trcEvents:     &eventMap{},
		chainRequests: make(chan chainRequest, MaxPendingRequests),
		chainEvents:   &eventMap{},
		log:           logger,
	}, nil
}

// StartResolvers launches goroutines for handling TRC and Cert requests that
// are not available in the local database. Outgoing (network) requests are
// throttled s.t. at most one request for each address and version is sent
// every MinimumDelta duration. Received objects are verified prior to
// insertion into the backing database, s.t. the database only contains
// verified data.
func (store *Store) StartResolvers(messenger infra.Messenger) error {
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
	store.startedFlag = true

	trcResolver := &trcResolver{
		msger:    messenger,
		trustdb:  store.trustdb,
		requests: store.trcRequests,
		events:   store.trcEvents,
		log:      store.log.New("goroutine", "trcResolver"),
	}
	go trcResolver.Run()
	chainResolver := &chainResolver{
		msger:    messenger,
		trustdb:  store.trustdb,
		requests: store.chainRequests,
		events:   store.chainEvents,
		log:      store.log.New("goroutine", "chainResolver"),
	}
	go chainResolver.Run()
	return nil
}

func (store *Store) getTRC(ctx context.Context, req trcRequest) (*trc.TRC, error) {
	for {
		// Attempt to get the TRC from the local cache
		if trc, err := store.trustdb.GetTRCVersionCtx(ctx, req.isd, req.version); err != nil {
			return nil, err
		} else if trc != nil {
			return trc, nil
		}
		// TRC not found, forward a request to the background TRC resolver
		if err := store.issueTRCRequest(ctx, req); err != nil {
			return nil, err
		}
	}
}

func (store *Store) issueTRCRequest(ctx context.Context, req trcRequest) error {
	select {
	case store.trcRequests <- req:
	default:
		return common.NewBasicError("Unable to request TRC, queue full",
			nil, "isd", req.isd, "version", req.version)
	}
	// Block waiting for request to be finalized
	select {
	case <-store.trcEvents.Wait(req.Key()):
		// Try to load version from map again
		return nil
	case <-ctx.Done():
		// Context expired while waiting
		return common.NewBasicError("Context canceled while waiting for TRC",
			nil, "isd", req.isd, "version", req.version)
	}
}

func (store *Store) getChain(ctx context.Context, req chainRequest) (*cert.Chain, error) {
	for {
		// Attempt to get the Chain from the local cache
		if chain, err := store.trustdb.GetChainVersionCtx(ctx, req.ia, req.version); err != nil {
			return nil, err
		} else if chain != nil {
			return chain, nil
		}
		// Chain not found, forward the request to the background Chain resolver
		if err := store.issueChainRequest(ctx, req); err != nil {
			return nil, err
		}
	}
}

func (store *Store) issueChainRequest(ctx context.Context, req chainRequest) error {
	select {
	case store.chainRequests <- req:
	default:
		return common.NewBasicError("Unable to request Chain, queue full",
			nil, "ia", req.ia, "version", req.version)
	}
	// Block waiting for request to be finalized
	select {
	case <-store.chainEvents.Wait(req.Key()):
		// Try to load version from map again
		return nil
	case <-ctx.Done():
		// Context expired while waiting
		return common.NewBasicError("Context canceled while waiting for Chain",
			nil, "ia", req.ia, "version", req.version)
	}
}

// NewTRCReqHandler initializes a handler for TRC request data coming from peer.
func (store *Store) NewTRCReqHandler(data, _ proto.Cerealizable, peer net.Addr) (infra.Handler, error) {
	trcReq, ok := data.(*cert_mgmt.TRCReq)
	if !ok {
		return nil, common.NewBasicError("wrong message type, expected cert_mgmt.TRCReq", nil,
			"msg", data, "type", common.TypeOf(data))
	}
	reqObject := &trcReqHandler{
		data:  trcReq,
		peer:  peer,
		cache: store,
		log:   store.log,
	}
	return reqObject, nil
}

// NewChainReqHandler initializes a handler for TRC request data coming from peer.
func (store *Store) NewChainReqHandler(data, _ proto.Cerealizable, peer net.Addr) (infra.Handler, error) {
	chainReq, ok := data.(*cert_mgmt.ChainReq)
	if !ok {
		return nil, common.NewBasicError("wrong message type, expected cert_mgmt.ChainReq", nil,
			"msg", data, "type", common.TypeOf(data))
	}
	reqObject := &chainReqHandler{
		data:  chainReq,
		peer:  peer,
		cache: store,
		log:   store.log,
	}
	return reqObject, nil
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

var _ infra.Handler = (*trcReqHandler)(nil)

type trcReqHandler struct {
	data  *cert_mgmt.TRCReq
	cache *Store
	peer  net.Addr
	log   log.Logger
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
	subCtx, cancelF := context.WithTimeout(ctx, 3*time.Second)
	defer cancelF()

	// Only serve remote requests from the local database for now
	request := trcRequest{
		isd:     uint16(h.data.ISD),
		version: h.data.Version,
	}
	trc, err := h.cache.getTRC(ctx, request)
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
	if err := messenger.SendTRC(subCtx, trcMessage, nil); err != nil {
		h.log.Error("Messenger API error", "err", err)
	}
}

var _ infra.Handler = (*chainReqHandler)(nil)

type chainReqHandler struct {
	data  *cert_mgmt.ChainReq
	cache *Store
	peer  net.Addr
	log   log.Logger
}

func (h *chainReqHandler) Handle(ctx context.Context) {
	// TODO(scrye): this is very similar to the trcReqHandler.Handle
	panic("not implemented")
}

type trcRequest struct {
	isd      uint16
	version  uint64
	hint     net.Addr
	verifier *trc.TRC
}

func (req trcRequest) Key() string {
	return fmt.Sprintf("%d-%d", req.isd, req.version)
}

type chainRequest struct {
	ia       addr.ISD_AS
	version  uint64
	hint     net.Addr
	verifier *trc.TRC
}

func (req chainRequest) Key() string {
	return fmt.Sprintf("%d-%d", req.ia, req.version)
}

func (store *Store) GetCertificate(ctx context.Context, trail []TrustDescriptor,
	hint net.Addr) (*cert.Certificate, error) {
	var (
		// The trust TRC used to verify the next trust object
		verifierTRC *trc.TRC
		// Trail index that searches for the first trusted object in the trail
		idx = 0
		err error
	)

ForLoop:
	for idx = 0; idx < len(trail); idx++ {
		desc := trail[idx]
		switch desc.Type {
		case ChainDescriptor:
			if idx != 0 {
				return nil, common.NewBasicError("Chain descriptors must be on index 0", nil,
					"actual", idx)
			}
			chain, err := store.trustdb.GetChainVersionCtx(ctx, desc.IA, desc.ChainVersion)
			if err != nil {
				return nil, common.NewBasicError("Unable to read from database", err)
			}
			if chain != nil {
				// We have the needed chain already, we can return
				return chain.Leaf, nil
			}
		case TRCDescriptor:
			if idx == 0 {
				return nil, common.NewBasicError("TRC descriptors are not allowed on index 0", nil)
			}
			trcObj, err := store.trustdb.GetTRCVersionCtx(ctx, uint16(desc.IA.I), desc.TRCVersion)
			if err != nil {
				return nil, common.NewBasicError("Unable to read from database", err)
			}
			if trcObj != nil {
				// We found the root of trust in the database, we can now go
				// back and download/verify missing TRCs and certificate chains
				// starting from it.
				verifierTRC = trcObj
				break ForLoop
			}
		default:
			return nil, common.NewBasicError("Unknown descriptor type", nil, "type", desc.Type)
		}
	}

	if idx == len(trail) {
		// We've reached the end of the trust trail without finding any trusted object, abort
		return nil, common.NewBasicError("Unable to find trusted object when following trail", nil)
	}

	for {
		descriptor := trail[idx]
		switch descriptor.Type {
		case ChainDescriptor:
			request := chainRequest{
				ia:       descriptor.IA,
				version:  descriptor.ChainVersion,
				verifier: verifierTRC,
				hint:     hint,
			}
			chain, err := store.getChain(ctx, request)
			if err != nil {
				return nil, err
			}
			return chain.Leaf, nil
		case TRCDescriptor:
			request := trcRequest{
				isd:      uint16(descriptor.IA.I),
				version:  descriptor.TRCVersion,
				verifier: verifierTRC,
				hint:     hint,
			}
			verifierTRC, err = store.getTRC(ctx, request)
			if err != nil {
				store.log.Info("Reply: ", "TRC", verifierTRC, "err", err)
				return nil, err
			}
		default:
			return nil, common.NewBasicError("Unknown descriptor type", nil, "type", descriptor.Type)
		}
		idx--
	}
}

type TrustDescriptor struct {
	TRCVersion   uint64
	ChainVersion uint64
	IA           addr.ISD_AS
	Type         TrustDescriptorType
}

type TrustDescriptorType uint64

const (
	ChainDescriptor TrustDescriptorType = iota
	TRCDescriptor
)
