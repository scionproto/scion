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
	"errors"
	"net"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/dedupe"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

const (
	// HandlerTimeout is the handler lifetime.
	HandlerTimeout = 3 * time.Second
)

var (
	// ErrNotFoundLocally indicates that a chain or TRC was not found locally.
	ErrNotFoundLocally = serrors.New("chain/TRC not found locally")
	// ErrMissingAuthoritative indicates that eventhough the trust store is
	// authoritative for the requested object, it wasn't found.
	ErrMissingAuthoritative = serrors.New("trust store is authoritative for requested object," +
		" and object was not found")
	// ErrNotFound indicates that a chain or TRC was not found even after a
	// network lookup.
	ErrNotFound = serrors.New("chain/TRC not found")
	// ErrChainVerification indicates the chain verification failed.
	ErrChainVerification = errors.New("chain verification failed")
	// ErrParse indicates the trust material could not be parsed.
	ErrParse = errors.New("unable to parse")
	// ErrInvalidResponse indicates an invalid response was received.
	ErrInvalidResponse = errors.New("invalid response")
)

var _ infra.ExtendedTrustStore = (*Store)(nil)

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
	config       Config
	// local AS
	ia    addr.IA
	log   log.Logger
	msger infra.Messenger
}

// NewStore initializes a TRC/Certificate Chain cache/resolver backed by db.
// Parameter local must specify the AS in which the trust store resides (which
// is used during request forwarding decisions).
func NewStore(db trustdb.TrustDB, local addr.IA, options Config, logger log.Logger) *Store {
	store := &Store{
		trustdb: db,
		ia:      local,
		config:  options,
		log:     logger,
	}
	return store
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
		return wrapErr(serrors.Wrap(ErrParse, err, "msg", trcMsg))
	}
	if trcObj == nil {
		return dedupe.Response{Data: nil}
	}

	if !req.version.IsLatest() && trcObj.Version != req.version {
		return wrapErr(serrors.WrapStr("remote server responded with bad version",
			ErrInvalidResponse, "got", trcObj.Version, "expected", req.version))
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
		return wrapErr(serrors.WrapStr("Unable to get CertChain from peer", err))
	}
	chain, err := chainMsg.Chain()
	if err != nil {
		return wrapErr(serrors.Wrap(ErrParse, err, "msg", chainMsg))
	}
	if chain == nil {
		return dedupe.Response{Data: nil}
	}
	if !req.version.IsLatest() && chain.Leaf.Version != req.version {
		return wrapErr(serrors.WrapStr("Remote server responded with bad version",
			ErrInvalidResponse, "got", chain.Leaf.Version, "expected", req.version))
	}
	if req.postHook != nil {
		return dedupe.Response{Data: chain, Error: req.postHook(ctx, chain)}
	}
	return dedupe.Response{Data: chain}
}

// GetTRC asks the trust store to return a valid and active TRC for isd. The
// optionally configured server is queried over the network if the TRC is not
// available locally. Otherwise, the default server is queried.
//
// FIXME(roosd): Currently this does not check whether the TRC is active.
func (store *Store) GetTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
	opts infra.TRCOpts) (*trc.TRC, error) {

	return store.getTRC(ctx, isd, version, opts, nil)
}

// getTRC attempts to grab the TRC from the database; if the TRC is not found,
// it follows up with a network request (if allowed). The options specify
// whether this function is allowed to create new network requests. Parameter
// client contains the node that caused the function to be called, or nil if the
// function was called due to a local feature.
func (store *Store) getTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
	opts infra.TRCOpts, client *snet.UDPAddr) (*trc.TRC, error) {

	l := metrics.LookupLabels{
		Client:    addrLocation(client, store.ia),
		Trigger:   metrics.FromCtx(ctx),
		ReqType:   metrics.TRCReq,
		CacheOnly: opts.LocalOnly,
		Result:    metrics.ErrInternal,
	}
	trcObj, err := store.trustdb.GetTRCVersion(ctx, isd, version)
	if err != nil {
		metrics.Store.Lookup(l.WithResult(metrics.ErrDB)).Inc()
		return nil, err
	}
	if trcObj != nil {
		metrics.Store.Lookup(l.WithResult(metrics.OkCached)).Inc()
		return trcObj, nil
	}
	if store.config.ServiceType == proto.ServiceType_cs &&
		store.config.TopoProvider.Get().Core() && store.ia.I == isd {
		// Core CS can't find TRC for its own ISD

		metrics.Store.Lookup(l.WithResult(metrics.ErrNotFoundAuth)).Inc()
		// XXX(kormat): Wrap ErrMissingAuthoritative with ErrNotFoundLocally to
		// simplify logic in LoadAuthoritativeTRC
		return nil, serrors.Wrap(ErrMissingAuthoritative, ErrNotFoundLocally,
			"isd", isd, "version", version, "client", client)
	}
	if opts.LocalOnly {
		metrics.Store.Lookup(l.WithResult(metrics.ErrNotFound)).Inc()
		return nil, serrors.WithCtx(ErrNotFoundLocally, "isd", isd, "version", version,
			"client", client)
	}
	if err := store.isLocal(client); err != nil {
		metrics.Store.Lookup(l.WithResult(metrics.ErrDenied)).Inc()
		return nil, err
	}
	if opts.Server == nil {
		opts.Server, err = store.ChooseServer(ctx, addr.IA{I: isd})
		if err != nil {
			metrics.Store.Lookup(l.WithResult(metrics.ErrInternal)).Inc()
			return nil, serrors.WrapStr("Error determining server to query", err,
				"isd", isd, "version", version)
		}
	}
	trcObj, err = store.getTRCFromNetwork(ctx, &trcRequest{
		isd:      isd,
		version:  version,
		id:       messenger.NextId(),
		server:   opts.Server,
		postHook: store.insertTRCHook(),
	})
	outLabels := store.getTRClabels(ctx, client, opts.Server, err)
	metrics.Store.Sent(outLabels).Inc()
	metrics.Store.Lookup(l.WithResult(outLabels.Result)).Inc()
	return trcObj, err
}

func (store *Store) getTRClabels(ctx context.Context, client *snet.UDPAddr, server net.Addr,
	err error) metrics.SentLabels {

	l := metrics.SentLabels{
		Client:  addrLocation(client, store.ia),
		Server:  addrLocation(server, store.ia),
		Trigger: metrics.FromCtx(ctx),
		ReqType: metrics.TRCReq,
		Result:  metrics.ErrInternal,
	}
	switch {
	case err == nil:
		l.Result = metrics.OkRequested
	case ctx.Err() != nil:
		l.Result = metrics.ErrTimeout
	case xerrors.Is(err, ErrNotFound):
		l.Result = metrics.ErrNotFound
	case xerrors.Is(err, ErrParse), xerrors.Is(err, ErrInvalidResponse):
		l.Result = metrics.ErrValidate
	}
	return l
}

func (store *Store) getTRCFromNetwork(ctx context.Context, req *trcRequest) (*trc.TRC, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "getTRCFromNet")
	defer span.Finish()
	responseC, cancelF, span := store.trcDeduper.Request(ctx, req)
	defer cancelF()
	defer span.Finish()
	select {
	case response := <-responseC:
		if response.Error != nil {
			return nil, response.Error
		}
		if response.Data == nil {
			return nil, ErrNotFound
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
	l := metrics.SentLabels{
		Trigger: metrics.FromCtx(ctx),
		ReqType: metrics.TRCPush,
		Server:  addrLocation(addr, store.ia),
		Result:  metrics.Success,
	}
	err = store.msger.SendTRC(ctx, &cert_mgmt.TRC{
		RawTRC: rawTRC,
	}, addr, messenger.NextId())
	if err != nil {
		metrics.Store.Sent(l.WithResult(metrics.ErrTransmit)).Inc()
		return common.NewBasicError("Failed to forward TRC", err)
	}
	metrics.Store.Sent(l).Inc()
	return nil
}

// GetChain asks the trust store to return a valid certificate chain for ia. The
// optionally configured server is queried over the network if the certificate
// chain is not available locally. Otherwise, the default server is queried.
func (store *Store) GetChain(ctx context.Context, ia addr.IA, version scrypto.Version,
	opts infra.ChainOpts) (*cert.Chain, error) {

	return store.getChain(ctx, ia, version, opts, nil)
}

func (store *Store) getChain(ctx context.Context, ia addr.IA, version scrypto.Version,
	opts infra.ChainOpts, client *snet.UDPAddr) (*cert.Chain, error) {

	l := metrics.LookupLabels{
		Client:    addrLocation(client, store.ia),
		Trigger:   metrics.FromCtx(ctx),
		ReqType:   metrics.ChainReq,
		CacheOnly: opts.LocalOnly,
		Result:    metrics.ErrInternal,
	}
	chain, err := store.trustdb.GetChainVersion(ctx, ia, version)
	if err != nil {
		metrics.Store.Lookup(l.WithResult(metrics.ErrDB)).Inc()
		return nil, err
	}
	if chain != nil {
		metrics.Store.Lookup(l.WithResult(metrics.OkCached)).Inc()
		return chain, nil
	}
	isCS := store.config.ServiceType == proto.ServiceType_cs
	isCore := store.config.TopoProvider.Get().Core()
	if (isCS && store.ia.Equal(ia)) ||
		(isCS && isCore && store.ia.I == ia.I) ||
		(store.config.MustHaveLocalChain && store.ia.Equal(ia) && version.IsLatest()) {
		// Either:
		// - CS can't find a cert for its own AS
		// or
		// - Core CS can't find cert for AS in own ISD
		// or
		// - Infra service doesn't have any version of its own cert

		metrics.Store.Lookup(l.WithResult(metrics.ErrNotFoundAuth)).Inc()
		return nil, serrors.WithCtx(ErrMissingAuthoritative, "ia", ia, "version", version,
			"client", client)
	}
	// Chain not found, so we'll need to fetch one. First, fetch the TRC we'll
	// need during certificate chain validation.
	trcOpts := infra.TRCOpts{
		TrustStoreOpts: opts.TrustStoreOpts,
	}
	trcObj, err := store.getTRC(ctx, ia.I, scrypto.LatestVer, trcOpts, client)
	if err != nil {
		metrics.Store.Lookup(l.WithResult(metrics.ErrTRC)).Inc()
		return nil, err
	}
	if opts.LocalOnly {
		metrics.Store.Lookup(l.WithResult(metrics.ErrNotFound)).Inc()
		return nil, serrors.WithCtx(ErrNotFoundLocally, "ia", ia, "version", version,
			"client", client)
	}
	if opts.Server == nil {
		var err error
		opts.Server, err = store.ChooseServer(ctx, ia)
		if err != nil {
			metrics.Store.Lookup(l.WithResult(metrics.ErrInternal)).Inc()
			return nil, err
		}
	}
	chain, err = store.getChainFromNetwork(ctx, &chainRequest{
		ia:       ia,
		version:  version,
		id:       messenger.NextId(),
		server:   opts.Server,
		postHook: store.newChainValidator(trcObj),
	})
	outLabels := store.getChainLabels(ctx, client, opts.Server, err)
	metrics.Store.Sent(outLabels).Inc()
	metrics.Store.Lookup(l.WithResult(outLabels.Result)).Inc()
	return chain, err
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
		l := metrics.SentLabels{
			Trigger: metrics.FromCtx(ctx),
			ReqType: metrics.ChainPush,
			Server:  addrLocation(addr, store.ia),
			Result:  metrics.Success,
		}
		err = store.msger.SendCertChain(ctx, &cert_mgmt.Chain{
			RawChain: rawChain,
		}, addr, messenger.NextId())
		if err != nil {
			metrics.Store.Sent(l.WithResult(metrics.ErrTransmit)).Inc()
			return common.NewBasicError("Failed to forward cert chain", err, "chain", chain)
		}
		metrics.Store.Sent(l).Inc()
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
			return serrors.WrapStr("Unable to store CertChain in database", err)
		}
		return nil
	}
}

func verifyChain(validator *trc.TRC, chain *cert.Chain) error {
	l := metrics.VerificationLabels{Type: metrics.Chain, Result: metrics.ErrVerify}
	if validator == nil {
		metrics.Store.Verification(l).Inc()
		return serrors.WithCtx(ErrChainVerification, "trc", validator, "chain", chain)
	}
	if err := chain.Verify(chain.Leaf.Subject, validator); err != nil {
		metrics.Store.Verification(l).Inc()
		return serrors.Wrap(ErrChainVerification, err, "trc", validator, "chain", chain)
	}
	metrics.Store.Verification(l.WithResult(metrics.Success)).Inc()
	return nil
}

func (store *Store) getChainLabels(ctx context.Context, client *snet.UDPAddr, server net.Addr,
	err error) metrics.SentLabels {

	l := metrics.SentLabels{
		Client:  addrLocation(client, store.ia),
		Server:  addrLocation(server, store.ia),
		Trigger: metrics.FromCtx(ctx),
		ReqType: metrics.ChainReq,
		Result:  metrics.ErrInternal,
	}
	switch {
	case err == nil:
		l.Result = metrics.OkRequested
	case ctx.Err() != nil:
		l.Result = metrics.ErrTimeout
	case xerrors.Is(err, ErrNotFound):
		l.Result = metrics.ErrNotFound
	case xerrors.Is(err, ErrParse), xerrors.Is(err, ErrInvalidResponse):
		l.Result = metrics.ErrValidate
	case xerrors.Is(err, ErrChainVerification):
		l.Result = metrics.ErrVerify
	}
	return l
}

// issueChainRequest requests a Chain from the trust store backend.
func (store *Store) getChainFromNetwork(ctx context.Context,
	req *chainRequest) (*cert.Chain, error) {

	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "getChainFromNetwork")
	defer span.Finish()
	responseC, cancelF, span := store.chainDeduper.Request(ctx, req)
	defer cancelF()
	defer span.Finish()
	select {
	case response := <-responseC:
		if response.Error != nil {
			return nil, response.Error
		}
		if response.Data == nil {
			return nil, ErrNotFound
		}
		return response.Data.(*cert.Chain), nil
	case <-ctx.Done():
		return nil, serrors.New("Context canceled while waiting for Chain",
			"ia", req.ia, "version", req.version)
	}
}

// LoadAuthoritativeCrypto loads the authoritative TRC and chain.
func (store *Store) LoadAuthoritativeCrypto(dir string) error {
	if err := store.LoadAuthoritativeTRC(dir); err != nil {
		return err
	}
	return store.LoadAuthoritativeChain(dir)
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
	ctx = metrics.CtxWith(ctx, metrics.Load)
	opts := infra.TRCOpts{TrustStoreOpts: infra.TrustStoreOpts{LocalOnly: true}}
	dbTRC, err := store.getTRC(ctx, store.ia.I, scrypto.LatestVer, opts, nil)
	switch {
	case err != nil && !xerrors.Is(err, ErrNotFoundLocally):
		// Unexpected error in trust store
		return common.NewBasicError("Failed to load TRC from store", err)
	case xerrors.Is(err, ErrNotFoundLocally) && fileTRC == nil:
		return serrors.New("No TRC found on disk or in trustdb")
	case xerrors.Is(err, ErrNotFoundLocally) && fileTRC != nil:
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
	ctx = metrics.CtxWith(ctx, metrics.Load)
	opts := infra.ChainOpts{TrustStoreOpts: infra.TrustStoreOpts{LocalOnly: true}}
	chain, err := store.getChain(ctx, store.ia, scrypto.LatestVer, opts, nil)
	switch {
	case err != nil && !xerrors.Is(err, ErrMissingAuthoritative):
		// Unexpected error in trust store
		return err
	case xerrors.Is(err, ErrMissingAuthoritative) && fileChain == nil:
		return serrors.New("No chain found on disk or in trustdb")
	case xerrors.Is(err, ErrMissingAuthoritative) && fileChain != nil:
		_, err := store.trustdb.InsertChain(ctx, fileChain)
		return err
	case err == nil && fileChain == nil:
		// Nothing to do, no chain to load from file but we already have one in the DB
		return nil
	default:
		// Found a chain file on disk, and found a chain in the DB. Check versions.
		switch {
		case fileChain.Leaf.Version > chain.Leaf.Version:
			_, err := store.trustdb.InsertChain(ctx, fileChain)
			return err
		case fileChain.Leaf.Version == chain.Leaf.Version:
			// Because it is the same version, check if the chains match
			if !fileChain.Equal(chain) {
				return common.NewBasicError("Conflicting chains found for same version", nil,
					"db", chain, "file", fileChain)
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
func (store *Store) isLocal(address *snet.UDPAddr) error {
	// We need to send out a network request, but only do so if we're
	// servicing a request coming from our own AS.
	if address == nil {
		return nil
	}

	if !store.ia.Equal(address.IA) {
		return common.NewBasicError("Object not found in DB, and recursion not "+
			"allowed for clients outside AS", nil, "addr", address)
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
	topo := store.config.TopoProvider.Get()
	if store.config.ServiceType != proto.ServiceType_cs {
		ret := snet.NewSVCAddr(store.ia, nil, nil, addr.SvcCS)
		return ret, nil
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
	ret := snet.NewSVCAddr(path.Destination(), path.Path(), path.OverlayNextHop(), addr.SvcCS)
	return ret, nil
}

// chooseDestCSIsd selects the CS to ask for crypto material, using the following strategy:
//  * a local core CS if destination is isd-local or any core CS.
//  * a remote core CS if destination is remote isd.
func (store *Store) chooseDestCSIsd(ctx context.Context, destination addr.IA,
	topo topology.Topology) (addr.ISD, error) {

	// For isd-local dests use local core.
	if destination.I == topo.IA().I {
		return topo.IA().I, nil
	}
	// For wildcards or any core dest use local core.
	if destination.A == 0 {
		return topo.IA().I, nil
	}
	opts := infra.ASInspectorOpts{RequiredAttributes: []infra.Attribute{infra.Core}}
	core, err := store.HasAttributes(ctx, destination, opts)
	if err != nil {
		return 0, err
	}
	if core {
		return topo.IA().I, nil
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

// ByAttributes returns a list of ASes in the specified ISD that
// hold all attributes.
func (store *Store) ByAttributes(ctx context.Context, isd addr.ISD,
	opts infra.ASInspectorOpts) ([]addr.IA, error) {

	ctx = metrics.CtxWith(ctx, metrics.ASInspector)
	trcOpts := infra.TRCOpts{TrustStoreOpts: opts.TrustStoreOpts}
	trc, err := store.GetTRC(ctx, isd, scrypto.LatestVer, trcOpts)
	if err != nil {
		return nil, common.NewBasicError("unable to resolve TRC", err)
	}
	// TODO(roosd): This has to take Attributes into account when moving
	// to the new TRC format.
	return trc.CoreASes.ASList(), nil
}

// HasAttributes indicates whether an AS holds all the specified attributes.
// The first return value is always false for non-primary ASes.
func (store *Store) HasAttributes(ctx context.Context, ia addr.IA,
	opts infra.ASInspectorOpts) (bool, error) {

	ctx = metrics.CtxWith(ctx, metrics.ASInspector)
	trcOpts := infra.TRCOpts{TrustStoreOpts: opts.TrustStoreOpts}
	trc, err := store.GetTRC(ctx, ia.I, scrypto.LatestVer, trcOpts)
	if err != nil {
		return false, common.NewBasicError("unable to resolve TRC", err)
	}
	_, ok := trc.CoreASes[ia]
	if !ok {
		return false, nil
	}
	// TODO(roosd): This has to take Attributes into account when moving
	// to the new TRC format.
	return true, nil
}

// wrapErr build a dedupe.Response object containing nil data and error err.
func wrapErr(err error) dedupe.Response {
	return dedupe.Response{Error: err}
}
