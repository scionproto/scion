// Copyright 2018 ETH Zurich
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

// Package trust defines type Store, a unified interface for TRC and Certificate
// retrieval.
package trust

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/dedupe"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

const (
	// Handler lifetime
	HandlerTimeout = 3 * time.Second
)

var (
	ErrNotFoundLocally      = "Chain/TRC not found locally"
	ErrMissingAuthoritative = "Trust store is authoritative for requested object," +
		" and object was not found"
	ErrNotFound = "Chain/TRC not found"
)

var _ infra.TrustStore = (*Store)(nil)

// Store manages requests for TRC and Certificate Chain objects.
//
// Chain and TRC requests from the local process (running the trust store)  are
// handled by GetValidChain/GetChain and GetValidTRC/GetTRC respectively, while
// requests from other services can be handled via NewXxxReqHandler methods.
//
// By default, a Store object can only return objects that are already present
// in the database. To allow a Store to use the SCION network to retrieve
// objects from other infrastructure services, an infra.Messenger must be set
// with SetMessenger.
//
// Store is backed by a database in package
// go/lib/infra/modules/trust/trustdb.
type Store struct {
	mu           sync.Mutex
	trustdb      trustdb.TrustDB
	trcDeduper   dedupe.Deduper
	chainDeduper dedupe.Deduper
	config       *Config
	// local AS
	ia    addr.IA
	log   log.Logger
	msger infra.Messenger
}

// NewStore initializes a TRC/Certificate Chain cache/resolver backed by db.
// Parameter local must specify the AS in which the trust store resides (which
// is used during request forwarding decisions).
func NewStore(db trustdb.TrustDB, local addr.IA,
	options *Config, logger log.Logger) (*Store, error) {

	if options == nil {
		options = &Config{}
	}
	store := &Store{
		trustdb: db,
		ia:      local,
		config:  options,
		log:     logger,
	}
	return store, nil
}

// SetMessenger enables network access for the trust store via msger. The
// messenger can only be set once.
func (store *Store) SetMessenger(msger infra.Messenger) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if store.msger != nil {
		panic("messenger already set")
	}
	store.msger = msger
	store.trcDeduper = dedupe.New(store.trcRequestFunc, 0, 0)
	store.chainDeduper = dedupe.New(store.chainRequestFunc, 0, 0)
}

// trcRequestFunc is the dedupe.RequestFunc for TRC requests.
func (store *Store) trcRequestFunc(ctx context.Context, request dedupe.Request) dedupe.Response {
	req := request.(*trcRequest)
	trcReqMsg := &cert_mgmt.TRCReq{
		ISD:       req.isd,
		Version:   req.version,
		CacheOnly: req.cacheOnly,
	}
	trcMsg, err := store.msger.GetTRC(ctx, trcReqMsg, req.server, req.id)
	if err != nil {
		return wrapErr(err)
	}
	trcObj, err := trcMsg.TRC()
	if err != nil {
		return wrapErr(common.NewBasicError("Unable to parse TRC message", err, "msg", trcMsg))
	}
	if trcObj == nil {
		return dedupe.Response{Data: nil}
	}

	if req.version != scrypto.LatestVer && trcObj.Version != req.version {
		return wrapErr(common.NewBasicError("Remote server responded with bad version", nil,
			"got", trcObj.Version, "expected", req.version))
	}

	if req.postHook != nil {
		return dedupe.Response{Data: trcObj, Error: req.postHook(ctx, trcObj)}
	}
	return dedupe.Response{Data: trcObj}
}

// chainRequestFunc is the dedupe.RequestFunc for Chain requests.
func (store *Store) chainRequestFunc(ctx context.Context, request dedupe.Request) dedupe.Response {
	req := request.(*chainRequest)
	chainReqMsg := &cert_mgmt.ChainReq{
		RawIA:     req.ia.IAInt(),
		Version:   req.version,
		CacheOnly: req.cacheOnly,
	}
	chainMsg, err := store.msger.GetCertChain(ctx, chainReqMsg, req.server, req.id)
	if err != nil {
		return wrapErr(common.NewBasicError("Unable to get CertChain from peer", err))
	}
	chain, err := chainMsg.Chain()
	if err != nil {
		return wrapErr(common.NewBasicError("Unable to parse CertChain message", err))
	}
	if chain == nil {
		return dedupe.Response{Data: nil}
	}
	if req.version != scrypto.LatestVer && chain.Leaf.Version != req.version {
		return wrapErr(common.NewBasicError("Remote server responded with bad version", nil,
			"got", chain.Leaf.Version, "expected", req.version))
	}
	if req.postHook != nil {
		return dedupe.Response{Data: chain, Error: req.postHook(ctx, chain)}
	}
	return dedupe.Response{Data: chain}
}

// GetValidTRC asks the trust store to return a valid TRC for isd. Server is
// queried over the network if the TRC is not available locally. Otherwise, the
// default server is queried.
func (store *Store) GetValidTRC(ctx context.Context, isd addr.ISD,
	server net.Addr) (*trc.TRC, error) {

	// FIXME(scrye): fall back to getTRC for now, although getValidTRC should
	// perform additional validations in the future.
	return store.getTRC(ctx, isd, scrypto.LatestVer, true, nil, server)
}

// GetValidCachedTRC asks the trust store to return a valid TRC for isd without
// accessing the network.
func (store *Store) GetValidCachedTRC(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
	trcObj, err := store.getTRC(ctx, isd, scrypto.LatestVer, false, nil, nil)
	if err != nil {
		return nil, common.NewBasicError(ErrNotFoundLocally, err)
	}
	return trcObj, nil
}

// GetTRC asks the trust store to return a TRC of the requested
// version without performing any verification. If the TRC is not available, it
// is requested from the authoritative CS.
func (store *Store) GetTRC(ctx context.Context,
	isd addr.ISD, version uint64) (*trc.TRC, error) {

	return store.getTRC(ctx, isd, version, true, nil, nil)
}

// getTRC attempts to grab the TRC from the database; if the TRC is not found,
// it follows up with a network request (if allowed).  Parameter recurse
// specifies whether this function is allowed to create new network requests.
// Parameter client contains the node that caused the function to be called,
// or nil if the function was called due to a local feature.
func (store *Store) getTRC(ctx context.Context, isd addr.ISD, version uint64,
	recurse bool, client, server net.Addr) (*trc.TRC, error) {

	trcObj, err := store.trustdb.GetTRCVersion(ctx, isd, version)
	if err != nil || trcObj != nil {
		return trcObj, err
	}
	if !recurse {
		return nil, common.NewBasicError(ErrNotFoundLocally, nil, "isd", isd, "version", version,
			"client", client)
	}
	if err := store.isLocal(client); err != nil {
		return nil, err
	}
	if server == nil {
		server, err = store.ChooseServer(ctx, addr.IA{I: isd})
		if err != nil {
			return nil, common.NewBasicError("Error determining server to query", err,
				"isd", isd, "version", version)
		}
	}
	return store.getTRCFromNetwork(ctx, &trcRequest{
		isd:      isd,
		version:  version,
		id:       messenger.NextId(),
		server:   server,
		postHook: store.insertTRCHook(),
	})
}

func (store *Store) getTRCFromNetwork(ctx context.Context, req *trcRequest) (*trc.TRC, error) {
	responseC, cancelF := store.trcDeduper.Request(req)
	defer cancelF()
	select {
	case response := <-responseC:
		if response.Error != nil {
			return nil, response.Error
		}
		if response.Data == nil {
			return nil, common.NewBasicError(ErrNotFound, nil)
		}
		return response.Data.(*trc.TRC), nil
	case <-ctx.Done():
		return nil, common.NewBasicError("Context done while waiting for TRC",
			ctx.Err(), "isd", req.isd, "version", req.version)
	}
}

func (store *Store) insertTRCHook() ValidateTRCFunc {
	if store.config.ServiceType == proto.ServiceType_ps {
		return store.insertTRCHookForwarding
	}
	return store.insertTRCHookLocal
}

// insertTRCHookLocal always inserts the TRC into the database.
func (store *Store) insertTRCHookLocal(ctx context.Context, trcObj *trc.TRC) error {
	if _, err := store.trustdb.InsertTRC(ctx, trcObj); err != nil {
		return common.NewBasicError("Unable to store TRC in database", err)
	}
	return nil
}

// insertTRCHookForwarding always inserts the TRC into the database and forwards it to the CS.
func (store *Store) insertTRCHookForwarding(ctx context.Context, trcObj *trc.TRC) error {
	if err := store.insertTRCHookLocal(ctx, trcObj); err != nil {
		return err
	}
	addr, err := store.ChooseServer(ctx, store.ia)
	if err != nil {
		return common.NewBasicError("Failed to select server to forward TRC", err)
	}
	rawTRC, err := trcObj.Compress()
	if err != nil {
		return common.NewBasicError("Failed to compress TRC for forwarding", err)
	}
	err = store.msger.SendTRC(ctx, &cert_mgmt.TRC{
		RawTRC: rawTRC,
	}, addr, messenger.NextId())
	if err != nil {
		return common.NewBasicError("Failed to forward TRC", err)
	}
	return nil
}

// GetValidChain asks the trust store to return a valid certificate chain for ia.
// Server is queried over the network if the chain is not available locally.
func (store *Store) GetValidChain(ctx context.Context, ia addr.IA, ver uint64,
	server net.Addr) (*cert.Chain, error) {

	return store.getValidChain(ctx, ia, ver, true, nil, server)
}

func (store *Store) getValidChain(ctx context.Context, ia addr.IA, ver uint64,
	recurse bool, client, server net.Addr) (*cert.Chain, error) {

	chain, err := store.trustdb.GetChainVersion(ctx, ia, ver)
	if err != nil || chain != nil {
		return chain, err
	}
	if store.config.MustHaveLocalChain && store.ia.Equal(ia) {
		return nil, common.NewBasicError(ErrMissingAuthoritative, nil,
			"requested_ia", ia)
	}
	// Chain not found, so we'll need to fetch one. First, fetch the TRC we'll
	// need during certificate chain validation.
	trcObj, err := store.getTRC(ctx, ia.I, scrypto.LatestVer, recurse, client, server)
	if err != nil {
		return nil, err
	}
	if !recurse {
		return nil, common.NewBasicError(ErrNotFoundLocally, nil, "ia", ia)
	}
	if server == nil {
		var err error
		server, err = store.ChooseServer(ctx, ia)
		if err != nil {
			return nil, err
		}
	}
	return store.getChainFromNetwork(ctx, &chainRequest{
		ia:       ia,
		version:  ver,
		id:       messenger.NextId(),
		server:   server,
		postHook: store.newChainValidator(trcObj),
	})
}

// GetChain asks the trust store to return a certificate chain of
// requested version without performing any verification. If the certificate
// chain is not available, it is requested from the authoritative CS.
func (store *Store) GetChain(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Chain, error) {

	return store.getChain(ctx, ia, version, true, nil)
}

// getChain attempts to grab the Certificate Chain from the database; if the
// Chain is not found, it follows up with a network request (if allowed).
// Parameter recurse specifies whether this function is allowed to create new
// network requests. Parameter client contains the node that caused the
// function to be called, or nil if the function was called due to a local
// feature.
func (store *Store) getChain(ctx context.Context, ia addr.IA, version uint64,
	recurse bool, client net.Addr) (*cert.Chain, error) {

	chain, err := store.trustdb.GetChainVersion(ctx, ia, version)
	if err != nil {
		return nil, common.NewBasicError("Error accessing trustdb", nil)
	}
	if chain != nil {
		return chain, nil
	}
	// If we're authoritative for the requested IA, error out now.
	if store.config.MustHaveLocalChain && store.ia.Equal(ia) {
		return nil, common.NewBasicError(ErrMissingAuthoritative, nil, "requested ia", ia)
	}
	if !recurse {
		return nil, common.NewBasicError("Chain not found in DB, and recursion disabled", nil,
			"ia", ia, "version", version, "client", client)
	}
	if err := store.isLocal(client); err != nil {
		return nil, err
	}
	server, err := store.ChooseServer(ctx, ia)
	if err != nil {
		return nil, common.NewBasicError("Error determining server to query", err,
			"requested_ia", ia, "requested_version", version)
	}
	return store.getChainFromNetwork(ctx, &chainRequest{
		ia:       ia,
		version:  version,
		id:       messenger.NextId(),
		server:   server,
		postHook: nil,
	})
}

func (store *Store) newChainValidator(validator *trc.TRC) ValidateChainFunc {
	if store.config.ServiceType == proto.ServiceType_ps {
		return store.newChainValidatorForwarding(validator)
	}
	return store.newChainValidatorLocal(validator)
}

// XXX(lukedirtwalker): This is not the final solution. It has many issues, see:
// https://github.com/scionproto/scion/issues/2083
func (store *Store) newChainValidatorForwarding(validator *trc.TRC) ValidateChainFunc {
	return func(ctx context.Context, chain *cert.Chain) error {
		if err := verifyChain(validator, chain); err != nil {
			return err
		}
		_, err := store.trustdb.InsertChain(ctx, chain)
		if err != nil {
			return common.NewBasicError("Unable to store CertChain in database", err)
		}
		addr, err := store.ChooseServer(ctx, store.ia)
		if err != nil {
			return common.NewBasicError("Failed to select server to forward cert chain", err)
		}
		rawChain, err := chain.Compress()
		if err != nil {
			return common.NewBasicError("Failed to compress chain for forwarding", err)
		}
		err = store.msger.SendCertChain(ctx, &cert_mgmt.Chain{
			RawChain: rawChain,
		}, addr, messenger.NextId())
		if err != nil {
			return common.NewBasicError("Failed to forward cert chain", err, "chain", chain)
		}
		return nil
	}
}

// newChainValidator returns a Chain validation callback with verifier as trust
// anchor. If validation succeeds, the certificate chain is also inserted in
// the trust database.
func (store *Store) newChainValidatorLocal(validator *trc.TRC) ValidateChainFunc {
	return func(ctx context.Context, chain *cert.Chain) error {
		if err := verifyChain(validator, chain); err != nil {
			return err
		}
		_, err := store.trustdb.InsertChain(ctx, chain)
		if err != nil {
			return common.NewBasicError("Unable to store CertChain in database", err)
		}
		return nil
	}
}

func verifyChain(validator *trc.TRC, chain *cert.Chain) error {
	if validator == nil {
		return common.NewBasicError("Chain verification failed, nil verifier", nil,
			"target", chain)
	}
	if err := chain.Verify(chain.Leaf.Subject, validator); err != nil {
		return common.NewBasicError("Chain verification failed", err)
	}
	return nil
}

// issueChainRequest requests a Chain from the trust store backend.
func (store *Store) getChainFromNetwork(ctx context.Context,
	req *chainRequest) (*cert.Chain, error) {

	responseC, cancelF := store.chainDeduper.Request(req)
	defer cancelF()
	select {
	case response := <-responseC:
		if response.Error != nil {
			return nil, response.Error
		}
		if response.Data == nil {
			return nil, common.NewBasicError(ErrNotFound, nil)
		}
		return response.Data.(*cert.Chain), nil
	case <-ctx.Done():
		return nil, common.NewBasicError("Context canceled while waiting for Chain",
			nil, "ia", req.ia, "version", req.version)
	}
}

func (store *Store) LoadAuthoritativeTRC(dir string) error {
	fileTRC, err := trc.TRCFromDir(
		dir,
		store.ia.I,
		func(err error) {
			store.log.Warn("Error reading TRC", "err", err)
		})
	if err != nil {
		return common.NewBasicError("Unable to load TRC from directory", err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	dbTRC, err := store.getTRC(ctx, store.ia.I, scrypto.LatestVer, false, nil, nil)
	switch {
	case err != nil && common.GetErrorMsg(err) != ErrNotFoundLocally:
		// Unexpected error in trust store
		return common.NewBasicError("Failed to TRC from store", err)
	case common.GetErrorMsg(err) == ErrNotFoundLocally && fileTRC == nil:
		return common.NewBasicError("No TRC found on disk or in trustdb", nil)
	case common.GetErrorMsg(err) == ErrNotFoundLocally && fileTRC != nil:
		if _, err := store.trustdb.InsertTRC(ctx, fileTRC); err != nil {
			return common.NewBasicError("Failed to insert TRC in trust db", err)
		}
		return nil
	case err == nil && fileTRC == nil:
		// Nothing to do, no TRC to load from file but we already have one in the DB
		return nil
	default:
		// Found a TRC file on disk, and found a TRC in the DB. Check versions.
		switch {
		case fileTRC.Version > dbTRC.Version:
			if _, err := store.trustdb.InsertTRC(ctx, fileTRC); err != nil {
				return common.NewBasicError("Failed to insert newer TRC in trust db", err)
			}
			return nil
		case fileTRC.Version == dbTRC.Version:
			// Because it is the same version, check if the TRCs match
			eq, err := fileTRC.JSONEquals(dbTRC)
			if err != nil {
				return common.NewBasicError("Unable to compare TRCs", err)
			}
			if !eq {
				return common.NewBasicError("Conflicting TRCs found for same version", nil,
					"db", dbTRC, "file", fileTRC)
			}
			return nil
		default:
			// file TRC is older than DB TRC, so we just ignore it
			return nil
		}
	}
}

func (store *Store) LoadAuthoritativeChain(dir string) error {
	fileChain, err := cert.ChainFromDir(
		dir,
		store.ia,
		func(err error) {
			store.log.Warn("Error reading Chain", "err", err)
		})
	if err != nil {
		return common.NewBasicError("Unable to load Chain from directory", err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	dbChain, err := store.getValidChain(ctx, store.ia, scrypto.LatestVer, false, nil, nil)
	switch {
	case err != nil && common.GetErrorMsg(err) != ErrMissingAuthoritative:
		// Unexpected error in trust store
		return err
	case common.GetErrorMsg(err) == ErrMissingAuthoritative && fileChain == nil:
		return common.NewBasicError("No chain found on disk or in trustdb", nil)
	case common.GetErrorMsg(err) == ErrMissingAuthoritative && fileChain != nil:
		_, err := store.trustdb.InsertChain(ctx, fileChain)
		return err
	case err == nil && fileChain == nil:
		// Nothing to do, no chain to load from file but we already have one in the DB
		return nil
	default:
		// Found a chain file on disk, and found a chain in the DB. Check versions.
		switch {
		case fileChain.Leaf.Version > dbChain.Leaf.Version:
			_, err := store.trustdb.InsertChain(ctx, fileChain)
			return err
		case fileChain.Leaf.Version == dbChain.Leaf.Version:
			// Because it is the same version, check if the chains match
			if !fileChain.Equal(dbChain) {
				return common.NewBasicError("Conflicting chains found for same version", nil,
					"db", dbChain, "file", fileChain)
			}
			return nil
		default:
			// file chain is older than DB chain, so we just ignore it
			return nil
		}
	}
}

// NewTRCReqHandler returns an infra.Handler for TRC requests coming from a
// peer, backed by the trust store. If recurse is set to true, the handler is
// allowed to issue new TRC requests over the network.  This method should only
// be used when servicing requests coming from remote nodes.
func (store *Store) NewTRCReqHandler(recurse bool) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &trcReqHandler{
			request: r,
			store:   store,
			recurse: recurse,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// NewChainReqHandler returns an infra.Handler for Certificate Chain
// requests coming from a peer, backed by the trust store. If recurse is set to
// true, the handler is allowed to issue new TRC and Certificate Chain requests
// over the network. This method should only be used when servicing requests
// coming from remote nodes.
func (store *Store) NewChainReqHandler(recurse bool) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := chainReqHandler{
			request: r,
			store:   store,
			recurse: recurse,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// NewTRCPushHandler returns an infra.Handler for TRC pushes coming from a
// peer, backed by the trust store. TRCs are pushed by local BSes during
// beaconing. Pushes are allowed from all local AS sources.
func (store *Store) NewTRCPushHandler() infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := trcPushHandler{
			request: r,
			store:   store,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// NewChainPushHandler returns an infra.Handler for Certifificate Chain pushes
// coming from a peer, backed by the trust store. Certificate chains are pushed
// by other ASes during core registration. Pushes are allowed from all
// local ISD sources.
func (store *Store) NewChainPushHandler() infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := chainPushHandler{
			request: r,
			store:   store,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

// isLocal returns an error if address is not part of the local AS (or if the
// check cannot be made).
func (store *Store) isLocal(address net.Addr) error {
	// We need to send out a network request, but only do so if we're
	// servicing a request coming from our own AS.
	if address != nil {
		switch saddr, ok := address.(*snet.Addr); {
		case !ok:
			return common.NewBasicError("Unable to determine AS of address",
				nil, "addr", address)
		case !store.ia.Equal(saddr.IA):
			return common.NewBasicError("Object not found in DB, and recursion not "+
				"allowed for clients outside AS", nil, "addr", address)
		}
	}
	return nil
}

// ChooseServer builds a CS address for crypto material regarding the
// destination AS.
//
// For non CSes this selects an AS-local CS.
// For CSes this selects
//  * a local core CS if destination is isd-local or any core CS.
//  * a remote core CS if destination is remote isd.
func (store *Store) ChooseServer(ctx context.Context, destination addr.IA) (net.Addr, error) {
	topo := itopo.Get()
	if store.config.ServiceType != proto.ServiceType_cs {
		return &snet.Addr{IA: store.ia, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}, nil
	}
	destISD, err := store.chooseDestCSIsd(ctx, destination, topo)
	if err != nil {
		return nil, common.NewBasicError("Unable to determine dest ISD to query", err)
	}
	path, err := store.config.Router.Route(ctx, addr.IA{I: destISD})
	if err != nil {
		return nil, common.NewBasicError("Unable to find path to any core AS", err,
			"isd", destISD)
	}
	a := &snet.Addr{IA: path.Destination(), Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	return a, nil
}

// chooseDestCSIsd selects the CS to ask for crypto material, using the following strategy:
//  * a local core CS if destination is isd-local or any core CS.
//  * a remote core CS if destination is remote isd.
func (store *Store) chooseDestCSIsd(ctx context.Context, destination addr.IA,
	topo *topology.Topo) (addr.ISD, error) {

	// For isd-local dests use local core.
	if destination.I == topo.ISD_AS.I {
		return topo.ISD_AS.I, nil
	}
	// For wildcards or any core dest use local core.
	if destination.A == 0 {
		return topo.ISD_AS.I, nil
	}
	trc, err := store.GetTRC(ctx, destination.I, scrypto.LatestVer)
	if err != nil {
		return 0, err
	}
	if trc.CoreASes.Contains(destination) {
		return topo.ISD_AS.I, nil
	}
	// For non-core dests in a remote isd use remote core.
	return destination.I, nil
}

func (store *Store) NewSigner(key common.RawBytes, meta infra.SignerMeta) (infra.Signer, error) {
	return NewBasicSigner(key, meta)
}

func (store *Store) NewVerifier() infra.Verifier {
	return NewBasicVerifier(store)
}

// wrapErr build a dedupe.Response object containing nil data and error err.
func wrapErr(err error) dedupe.Response {
	return dedupe.Response{Error: err}
}
