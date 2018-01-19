// Copyright 2017 ETH Zurich
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
	logext "github.com/inconshreveable/log15/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
)

const (
	// Maximum number of requests waiting to be picked up by the trust server.
	// If the maximum is reached and a goroutine attempts to register a new
	// request, it will receive an error.
	MaxPendingRequests = 64
)

// Store manages requests for TRC and Certificate Chain objects.
//
// Requests from local server logic are handled via GetXxx methods,
// while requests from other services can be handled via NewXxxHandler methods.
//
// By default, a Store object can only return objects that are already present
// in the database at path. To allow a Store to use the SCION network to
// retrieve objects from other infrastructure services, method StartResolvers
// must be called with an operational infra.Messenger object.
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
// every MinimumDelta duration. Received objects are not verified prior to
// insertion into the backing database.
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
		api:      messenger,
		trustdb:  store.trustdb,
		requests: store.trcRequests,
		events:   store.trcEvents,
		log:      store.log.New("id", logext.RandId(4), "goroutine", "trcResolver"),
	}
	go trcResolver.Run()
	chainResolver := &chainResolver{
		api:      messenger,
		trustdb:  store.trustdb,
		requests: store.chainRequests,
		events:   store.chainEvents,
		log:      store.log.New("id", logext.RandId(4), "goroutine", "chainResolver"),
	}
	go chainResolver.Run()
	return nil
}

func (store *Store) getTRC(ctx context.Context, request trcRequest) (*trc.TRC, error) {
	for {
		// Attempt to get the TRC from the local cache
		if trc, ok, err := store.trustdb.GetTRCVersionCtx(ctx, request.isd, request.version); err != nil {
			return nil, err
		} else if ok {
			return trc, nil
		}
		// TRC not found, forward a request to the background TRC resolver
		if err := store.issueTRCRequest(ctx, request); err != nil {
			return nil, err
		}
	}
}

func (store *Store) issueTRCRequest(ctx context.Context, request trcRequest) error {
	select {
	case store.trcRequests <- request:
	default:
		return common.NewBasicError("Unable to request TRC, queue full",
			nil, "isd", request.isd, "version", request.version)
	}
	// Block waiting for request to be finalized
	select {
	case <-store.trcEvents.Wait(request):
		// Try to load version from map again
		return nil
	case <-ctx.Done():
		// Context expired while waiting
		return common.NewBasicError("Context canceled while waiting for TRC",
			nil, "isd", request.isd, "version", request.version)
	}
}

func (store *Store) getChain(ctx context.Context, request chainRequest) (*cert.Chain, error) {
	for {
		// Attempt to get the Chain from the local cache
		if chain, ok, err := store.trustdb.GetChainVersionCtx(ctx, request.ia, request.version); err != nil {
			return nil, err
		} else if ok {
			return chain, nil
		}
		// Chain not found, forward the request to the background Chain resolver
		if err := store.issueChainRequest(ctx, request); err != nil {
			return nil, err
		}
	}
}

func (store *Store) issueChainRequest(ctx context.Context, request chainRequest) error {
	select {
	case store.chainRequests <- request:
	default:
		return common.NewBasicError("Unable to request Chain, queue full",
			nil, "ia", request.ia, "version", request.version)
	}
	// Block waiting for request to be finalized
	select {
	case <-store.chainEvents.Wait(request):
		// Try to load version from map again
		return nil
	case <-ctx.Done():
		// Context expired while waiting
		return common.NewBasicError("Context canceled while waiting for Chain",
			nil, "ia", request.ia, "version", request.version)
	}
}

// NewTRCReqHandler initializes a handler for TRC request data coming from peer.
func (store *Store) NewTRCReqHandler(data, _ interface{}, peer net.Addr) (infra.Handler, error) {
	trcReq, ok := data.(*cert_mgmt.TRCReq)
	if !ok {
		return nil, common.NewBasicError("wrong message type, expected cert_mgmt.TRCReq", nil,
			"msg", data)
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
func (store *Store) NewChainReqHandler(data, _ interface{}, peer net.Addr) (infra.Handler, error) {
	chainReq, ok := data.(*cert_mgmt.ChainReq)
	if !ok {
		return nil, common.NewBasicError("wrong message type, expected cert_mgmt.ChainReq", nil,
			"msg", data)
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

// Includes goroutine-specific state
type trcReqHandler struct {
	data  *cert_mgmt.TRCReq
	cache *Store
	peer  net.Addr
	log   log.Logger
}

func (handler *trcReqHandler) Handle(ctx context.Context) {
	v := ctx.Value(infra.MessengerContextKey)
	if v == nil {
		handler.log.Warn("Unable to service request, no Messenger interface found")
		return
	}
	messenger, ok := v.(infra.Messenger)
	if !ok {
		handler.log.Warn("Unable to service request, bad Messenger interface found")
		return
	}
	subCtx, cancelF := context.WithTimeout(ctx, 3*time.Second)
	defer cancelF()

	// Only serve remote requests from the local database for now
	request := trcRequest{
		isd:     uint16(handler.data.ISD),
		version: handler.data.Version,
	}
	trc, err := handler.cache.getTRC(ctx, request)
	if err != nil {
		handler.log.Error("Unable to retrieve TRC", "err", err)
		return
	}

	// FIXME(scrye): avoid recompressing this for every request
	rawTRC, err := trc.Compress()
	if err != nil {
		handler.log.Warn("Unable to compress TRC", "err", err)
		return
	}
	trcMessage := &cert_mgmt.TRC{
		RawTRC: rawTRC,
	}
	if err := messenger.SendTRC(subCtx, trcMessage, nil); err != nil {
		handler.log.Error("Messenger API error", "err", err)
	}
}

var _ infra.Handler = (*chainReqHandler)(nil)

// Includes goroutine-specific state
type chainReqHandler struct {
	data  *cert_mgmt.ChainReq
	cache *Store
	peer  net.Addr
	log   log.Logger
}

func (handler *chainReqHandler) Handle(ctx context.Context) {
	// TODO(scrye): this is very similar to the trcReqHandler.Handle
	panic("not implemented")
}

type trcRequest struct {
	isd      uint16
	version  uint64
	hint     net.Addr
	verifier *trc.TRC
}

type chainRequest struct {
	ia       addr.ISD_AS
	version  uint64
	hint     net.Addr
	verifier *trc.TRC
}

func (store *Store) GetCertificate(ctx context.Context, trail []TrustDescriptor, hint net.Addr) (*cert.Certificate, error) {
	var (
		// The trust TRC used to verify the next trust object
		verifierTRC *trc.TRC
		// Trail index that searches for the first trusted object in the trail
		idx = 0
		err error
	)

ForLoop:
	for idx = 0; idx < len(trail); idx++ {
		descriptor := trail[idx]
		switch descriptor.Type {
		case ChainDescriptor:
			if idx != 0 {
				return nil, common.NewBasicError("Chain descriptors are only allowed in trails on index 0", nil, "actual", idx)
			}
			chain, ok, err := store.trustdb.GetChainVersionCtx(ctx, descriptor.IA, descriptor.ChainVersion)
			if err != nil {
				return nil, common.NewBasicError("Unable to read from database", err)
			}
			if ok {
				// We have the needed chain already, we can return
				return chain.Leaf, nil
			}
		case TRCDescriptor:
			if idx == 0 {
				return nil, common.NewBasicError("TRC descriptors are not allowed in trail on index 0", nil)
			}
			trcObj, ok, err := store.trustdb.GetTRCVersionCtx(ctx, uint16(descriptor.IA.I), descriptor.TRCVersion)
			if err != nil {
				return nil, common.NewBasicError("Unable to read from database", err)
			}
			if ok {
				// We found the root of trust in the database, we can now go
				// back and download/verify missing TRCs and certificate chains
				// starting from it.
				verifierTRC = trcObj
				break ForLoop
			}
		default:
			return nil, common.NewBasicError("Unknown descriptor type", nil, "type", descriptor.Type)
		}
	}

	if idx == len(trail) {
		// We've reached the end of the trust trail without finding any trusted object, abort
		return nil, common.NewBasicError("Unable to find trusted object when following trust trail", nil)
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
