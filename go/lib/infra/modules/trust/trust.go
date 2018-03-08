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
	"sync/atomic"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/snet"
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
// Certificate requests from the local process (running the trust store)  are
// handled by GetCertificate, while requests from other services can be handled
// via XxxReqHandler methods.
//
// By default, a Store object can only return objects that are already present
// in the database. To allow a Store to use the SCION network to retrieve
// objects from other infrastructure services, method StartResolvers must be
// called with an operational infra.Messenger object.
//
// Currently Store is backed by a sqlite3 database in package
// go/lib/infra/modules/trust/trustdb.
type Store struct {
	trustdb *trustdb.DB
	// channel to send TRC requests from client goroutines to the backend
	// resolver
	trcRequests chan requestI
	// channel to send Certificate Chain requests from client goroutines to the
	// backend resolver
	chainRequests chan requestI
	// local AS
	ia  addr.IA
	log log.Logger

	// ID of the last infra message that was sent out by the Store
	msgID uint64
	// Used to serialize access to Close
	closeMutex sync.Mutex
	// Set to true once Closed successfully completes
	closedFlag bool

	// Used to serialize access to StartResolvers
	startMutex sync.Mutex
	// Set to true once StartResolvers successfully completes
	startedFlag bool
}

// NewStore initializes a TRC/Certificate Chain cache/resolver backed by db.
// Parameter local must specify the AS in which the trust store resides (which
// is used during request forwarding decisions). When sending infra messages,
// the trust store will use IDs starting from startID, and increment by one for
// each message.
func NewStore(db *trustdb.DB, local addr.IA, startID uint64, logger log.Logger) (*Store, error) {
	return &Store{
		trustdb:       db,
		trcRequests:   make(chan requestI, MaxPendingRequests),
		chainRequests: make(chan requestI, MaxPendingRequests),
		ia:            local,
		log:           logger,
		msgID:         startID,
	}, nil
}

// StartResolvers launches goroutines for handling TRC and Cert requests that
// are not available in the local database. Outgoing (network) requests are
// throttled s.t. at most one request for each address and version is sent
// every MinimumDelta duration. Received objects are verified prior to
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
// it follows up with a network request (if allowed).  Parameter recurse
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
			if !ok {
				return nil, common.NewBasicError("Unable to determine AS of requester",
					nil, "addr", requester)
			}
			if !store.ia.Eq(saddr.IA) {
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
	case err := <-req.completionChan:
		return err
	case <-ctx.Done():
		// Context expired while waiting
		return common.NewBasicError("Context canceled while waiting for TRC",
			nil, "isd", req.isd, "version", req.version)
	}
}

// getChain attempts to grab the Certificate Chain from the database; if the
// Chain is not found, it follows up with a network request (if allowed).
// Parameter recurse specifies whether this function is allowed to create new
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
			if !ok {
				return nil, common.NewBasicError("Unable to determine AS of requester",
					nil, "addr", requester)
			}
			if !store.ia.Eq(saddr.IA) {
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

// NewTRCReqHandler returns an infra.Handler for TRC requests coming from a
// peer, backed by the trust store. If recurse is set to true, the handler is
// allowed to issue new TRC requests over the network.  This method should only
// be used when servicing requests coming from remote nodes.
func (store *Store) NewTRCReqHandler(recurse bool) infra.Handler {
	handler := func(r *infra.Request) {
		handlerState := &trcReqHandler{
			request: r,
			store:   store,
			log:     store.log,
			recurse: recurse,
		}
		handlerState.Handle()
	}
	return infra.HandlerFunc(handler)
}

// NewChainReqHandler returns an infra.Handler for Certificate Chain
// requests coming from a peer, backed by the trust store. If recurse is set to
// true, the handler is allowed to issue new TRC and Certificate Chain requests
// over the network. This method should only be used when servicing requests
// coming from remote nodes.
func (store *Store) NewChainReqHandler(recurse bool) infra.Handler {
	handler := func(r *infra.Request) {
		handlerState := &chainReqHandler{
			request: r,
			store:   store,
			log:     store.log,
			recurse: recurse,
		}
		handlerState.Handle()
	}
	return infra.HandlerFunc(handler)
}

// NewPushTRCHandler returns an infra.Handler that verifies unsolicited TRCs coming from
// remote nodes. If the verification succeeds, the TRC is inserted into the
// backing trust database.
func (store *Store) NewPushTRCHandler() infra.Handler {
	handler := func(r *infra.Request) {
		handlerState := &trcPushHandler{
			request: r,
			store:   store,
			log:     store.log,
		}
		handlerState.Handle()
	}
	return infra.HandlerFunc(handler)
}

// NewPushChainHandler returns an infra.Handler that verifies unsolicited Certificate
// Chains coming form remote nodes. If the verification succeeds, the Chain is
// inserted into the backing trust database.
func (store *Store) NewPushChainHandler() infra.Handler {
	handler := func(r *infra.Request) {
		handlerState := &chainPushHandler{
			request: r,
			store:   store,
			log:     store.log,
		}
		handlerState.Handle()
	}
	return infra.HandlerFunc(handler)
}

func (store *Store) GetCertificate(ctx context.Context, trail []infra.TrustDescriptor,
	hint net.Addr) (*cert.Certificate, error) {

	verifierObj, err := store.getTrustObject(ctx, trail, hint)
	if err != nil {
		return nil, err
	}
	if verifierObj == nil {
		return nil, common.NewBasicError("certificate chain not found", nil, "trail", trail)
	}
	chain := verifierObj.(*cert.Chain)
	return chain.Leaf, nil
}

func (store *Store) GetTRC(ctx context.Context, trail []infra.TrustDescriptor,
	hint net.Addr) (*trc.TRC, error) {

	verifierObj, err := store.getTrustObject(ctx, trail, hint)
	if err != nil {
		return nil, err
	}
	if verifierObj == nil {
		return nil, common.NewBasicError("trc not found", nil, "trail", trail)
	}
	trcObj := verifierObj.(*trc.TRC)
	return trcObj, nil
}

// getTrustObject recursively follows trail to create a fully verified trust
// chain leading up to trail[0].  Given a trail composed of:
//   [Cert0, TRC0, TRC1, TRC2]
// getTrustObject first tries to see if Cert0 is in trustdb. If it's not, it
// recursively calls getTrustObject on new trail:
//   [TRC0, TRC1, TRC2]
// and eventually:
//   [TRC1, TRC2]
// Suppose TRC2 is in the database. The function returns (TRC2, nil). The
// caller now has access to TRC2, and needs to obtain TRC1. It issues a call to
// the backend passing TRC2 as a verifier. Once it gets TRC1, it returns it.
//
// TRC1 is then used to download TRC0, and finally TRC0 is used to download
// Cert0, and the recursion finishes.
func (store *Store) getTrustObject(ctx context.Context, trail []infra.TrustDescriptor,
	hint net.Addr) (interface{}, error) {

	if len(trail) == 0 {
		// We've reached the end of the trail and did not find a trust anchor,
		// propagate this information to the caller.
		return nil, nil
	}

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
	nextObj, err := store.getTrustObject(ctx, trail[1:], hint)
	if err != nil {
		return nil, err
	}
	if nextObj == nil {
		// Propagate the information that there is no trust anchor available at
		// the end of the trail
		return nil, nil
	}
	// Getting a panic on this trust assertion means the trust trail was
	// not valid (e.g., multiple chains were present, but this
	// functionality is not supported yet).
	nextTRC := nextObj.(*trc.TRC)

	// We have the next trust object, so we can issue a request to the backend
	// for the current trust object by passing it as the verifier.
	return store.fetchByDescriptor(ctx, trail[0], hint, nextTRC)
}

func (store *Store) queryByDescriptor(ctx context.Context,
	desc infra.TrustDescriptor) (interface{}, error) {

	switch desc.Type {
	case infra.ChainDescriptor:
		chain, err := store.trustdb.GetChainVersionCtx(ctx, desc.IA, desc.Version)
		if err != nil {
			return nil, common.NewBasicError("Query GetChainVersionCtx to trustdb failed", err)
		}
		if chain != nil {
			// We have the needed chain already, we can return
			return chain.Leaf, nil
		}
	case infra.TRCDescriptor:
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

func (store *Store) fetchByDescriptor(ctx context.Context, desc infra.TrustDescriptor,
	hint net.Addr, verifier *trc.TRC) (interface{}, error) {

	switch desc.Type {
	case infra.ChainDescriptor:
		request := chainRequest{
			ia:       desc.IA,
			version:  desc.Version,
			verifier: verifier,
			hint:     hint,
			id:       store.nextID(),
			errChan:  make(chan error, 1),
		}
		return store.getChain(ctx, request, true, nil)
	case infra.TRCDescriptor:
		request := trcRequest{
			isd:            uint16(desc.IA.I),
			version:        desc.Version,
			verifier:       verifier,
			hint:           hint,
			id:             store.nextID(),
			completionChan: make(chan error, 1),
		}
		return store.getTRC(ctx, request, true, nil)
	default:
		return nil, common.NewBasicError("Unknown descriptor type", nil, "type", desc.Type)
	}
}

// localTRCVerify will try to verify trcObj without any available
// side-information. localTRCVerify never issues requests to the backend
// resolvers, instead giving up if the required information is not already in
// the database.
func (store *Store) localTRCVerify(ctx context.Context, trcObj *trc.TRC) verificationResult {
	// FIXME(scrye): While cross signatures and ISD trails in pushes are not
	// implemented, always return success for all TRCs.
	return resultSuccessExists

	/*
		// If we already have the TRC for this ISD and version number, stop
		desc := infra.TrustDescriptor{
			IA:      addr.IA{I: int(trcObj.ISD), A: 0},
			Version: trcObj.Version,
			Type:    infra.TRCDescriptor,
		}
		if _, err := store.queryByDescriptor(ctx, desc); err != nil {
			return resultSuccessExists
		}

		// FIXME(scrye): This needs a closer look, as I'm not sure whether it is
		// intended behavior.  If we do not have the TRC, we need to find out how
		// to verify it. First, we check whether we have the previous version. If
		// we do, we need to check whether the verification succeeds. If we don't
		// have the previous version, we look into all the cross signer fields in the
		// pushed TRC, and for each one try to see if its ISD's TRC is in our trust
		// database. If it is and verification succeeds, accept it. TRCs that are
		// more than one hop away will fail this verification.
		verified := false
		for key := range trcObj.Signatures {
			if ia, err := addr.IAFromString(key); err == nil && ia.I != int(trcObj.ISD) {
				desc := infra.TrustDescriptor{
					IA:      addr.IA{I: int(trcObj.ISD), A: 0},
					Version: 0, // Ask for max
					Type:    infra.TRCDescriptor,
				}
				genericObj, err := store.queryByDescriptor(ctx, desc)
				if err != nil {
					// Try next one
					continue
				}
				verifierTRC := genericObj.(*trc.TRC)

				// Object found, check for cross-signature
				if _, err := trcObj.Verify(verifierTRC); err != nil {
					// FIXME(scrye): The fact that verification failed points to a
					// forged TRC. Deciding to continue is risky, as it might lead
					// to broken trust chains. E.g. X trusts Y and Z, Y trusts V
					// but Z doesn't trust V. Stopping verification here should
					// probably be the desired approach, _however_, doing so means
					// that verification can return different results depending on
					// the order in which trcObj.Signatures is iterated through.
					// For now, just try every TRC.
					continue
				}
				verified = true
			}
		}
		if verified {
			return resultSuccessVerified
		}
		return resultFailure
	*/
}

// localChainVerify will try to verify chain without any available
// side-information. localChainVerify never issues requests to the backend
// resolvers, instead giving up if the required information is not already in
// the database.
func (store *Store) localChainVerify(ctx context.Context, chain *cert.Chain) verificationResult {
	// If we already have the Chain for this AS and version number, stop
	desc := infra.TrustDescriptor{
		IA:      chain.Leaf.Subject,
		Version: chain.Leaf.Version,
		Type:    infra.ChainDescriptor,
	}
	if _, err := store.queryByDescriptor(ctx, desc); err != nil {
		return resultSuccessExists
	}

	trcDesc := infra.TrustDescriptor{
		IA:      chain.Core.Issuer,
		Version: chain.Core.TRCVersion,
		Type:    infra.TRCDescriptor,
	}
	genericObj, err := store.queryByDescriptor(ctx, trcDesc)
	if err != nil {
		// TRC missing
		return resultFailure
	}
	trcObj := genericObj.(*trc.TRC)

	// Verify the chain using the TRC we retrieved
	if err := chain.Verify(chain.Leaf.Subject, trcObj); err != nil {
		return resultFailure
	}
	return resultSuccessVerified
}

func (store *Store) nextID() uint64 {
	return atomic.AddUint64(&store.msgID, 1)
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

// verificationResult is used by localXxx methods to inform the caller whether
// (and why) the verification succeeded/failed.
type verificationResult uint16

const (
	// Returned when an object is verified, and it already exists in the database
	resultSuccessExists verificationResult = iota
	// Returned when an object is successfully verified, and is not currently in the database
	resultSuccessVerified
	// Returned when verification failed
	resultFailure
)
