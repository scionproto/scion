// Copyright 2019 Anapaya Systems
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
	"errors"
	"time"

	"github.com/opentracing/opentracing-go"
	opentracingext "github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrInactive indicates that the requested material is inactive.
var ErrInactive = serrors.New("inactive")

// CryptoProvider provides crypto material. A crypto provider can spawn network
// requests if necessary and permitted.
type CryptoProvider interface {
	// AnnounceTRC announces the existence of a TRC, it must be called before
	// verifying a signature based on a certificate chain to ensure the TRC in
	// the signature source is available to the CryptoProvider.
	AnnounceTRC(context.Context, TRCID, infra.TRCOpts) error
	// GetTRC asks the trust store to return a valid and active TRC for isd,
	// unless inactive TRCs are specifically allowed. The optionally configured
	// server is queried over the network if the TRC is not available locally.
	// Otherwise, the default server is queried. How the default server is
	// determined differs between implementations.
	GetTRC(context.Context, TRCID, infra.TRCOpts) (*trc.TRC, error)
	// GetRawTRC behaves the same as GetTRC, except returning the raw signed TRC.
	GetRawTRC(context.Context, TRCID, infra.TRCOpts) ([]byte, error)
	// GetRawChain asks the trust store to return a valid and active certificate
	// chain, unless inactive chains are specifically allowed. The optionally
	// configured server is queried over the network if the certificate chain is
	// not available locally. Otherwise, the default server is queried. How the
	// default server is determined differs between implementations.
	GetRawChain(context.Context, ChainID, infra.ChainOpts) ([]byte, error)
	// GetASKey returns from trust store the public key required to verify
	// signature originated from an AS.
	GetASKey(context.Context, ChainID, infra.ChainOpts) (scrypto.KeyMeta, error)
}

// TRCID identifies a TRC.
type TRCID struct {
	ISD     addr.ISD
	Version scrypto.Version
}

// ChainID identifies a chain.
type ChainID struct {
	IA      addr.IA
	Version scrypto.Version
}

// Provider provides crypto material. A crypto provider can spawn network
// requests if necessary and permitted.
type Provider struct {
	DB       DBRead
	Recurser Recurser
	Resolver Resolver
	Router   Router
}

// AnnounceTRC announces the existence of a TRC, it must be called before
// verifying a signature based on a certificate chain to ensure the TRC in
// the signature source is available to the CryptoProvider.
func (p Provider) AnnounceTRC(ctx context.Context, id TRCID, opts infra.TRCOpts) error {
	// This could be implemented more efficiently, but comes with additional
	// complexity in the code.
	opts.AllowInactive = true
	_, _, err := p.getCheckedTRC(ctx, id, opts)
	return err
}

// GetTRC asks the trust store to return a valid and active TRC for isd,
// unless inactive TRCs are specifically allowed. The optionally configured
// server is queried over the network if the TRC is not available locally.
// Otherwise, the default server is queried. How the default server is
// determined differs between implementations.
func (p Provider) GetTRC(ctx context.Context, id TRCID, opts infra.TRCOpts) (*trc.TRC, error) {
	l := metrics.ProviderLabels{Type: metrics.TRC, Trigger: metrics.FromCtx(ctx)}
	t, _, err := p.getCheckedTRC(ctx, id, opts)
	metrics.Provider.Request(l.WithResult(errToLabel(err))).Inc()
	return t, err
}

// GetRawTRC behaves the same as GetTRC, except returning the raw signed TRC.
func (p Provider) GetRawTRC(ctx context.Context, id TRCID, opts infra.TRCOpts) ([]byte, error) {
	l := metrics.ProviderLabels{Type: metrics.TRC, Trigger: metrics.FromCtx(ctx)}
	_, raw, err := p.getCheckedTRC(ctx, id, opts)
	metrics.Provider.Request(l.WithResult(errToLabel(err))).Inc()
	return raw, err
}

func (p Provider) getCheckedTRC(parentCtx context.Context, id TRCID,
	opts infra.TRCOpts) (*trc.TRC, []byte, error) {

	span, ctx := opentracing.StartSpanFromContext(parentCtx, "get_checked_trc")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("isd", id.ISD)
	span.SetTag("version", id.Version)
	logger := log.FromCtx(ctx)

	decTRC, err := p.getTRC(ctx, id, opts)
	if err != nil {
		return nil, nil, serrors.WrapStr("unable to get requested TRC", err,
			"isd", id.ISD, "version", id.Version)
	}
	if opts.AllowInactive {
		return decTRC.TRC, decTRC.Raw, nil
	}
	logger.Trace("[TrustStore:Provider] Get latest TRC info", "isd", id.ISD)
	info, err := p.DB.GetTRCInfo(ctx, TRCID{ISD: id.ISD, Version: scrypto.LatestVer})
	if err != nil {
		return nil, nil, serrors.WrapStr("unable to get latest TRC info", err)
	}
	logger.Trace("[TrustStore:Provider] Latest TRC info", "isd", id.ISD, "version", info.Version)
	switch {
	case info.Version > decTRC.TRC.Version+1:
		return nil, nil, serrors.WrapStr("inactivated by latest TRC version", ErrInactive,
			"latest", info.Version)
	case info.Version == decTRC.TRC.Version+1 && graceExpired(info):
		return nil, nil, serrors.WrapStr("grace period has passed", ErrInactive,
			"end", info.Validity.NotBefore.Add(info.GracePeriod), "latest", info.Version)
	case !decTRC.TRC.Validity.Contains(time.Now()):
		if !id.Version.IsLatest() || opts.LocalOnly {
			return nil, nil, serrors.WrapStr("requested TRC expired", ErrInactive,
				"validity", decTRC.TRC.Validity)
		}
		// There might exist a more recent TRC that is not available locally
		// yet. Fetch it if the latest version was requested and recursion
		// is allowed.
		logger.Debug("[TrustStore:Provider] Local latest TRC inactive, fetching from network",
			"isd", id.ISD)
		fetched, err := p.fetchTRC(ctx, TRCID{ISD: id.ISD, Version: scrypto.LatestVer}, opts)
		if err != nil {
			return nil, nil, serrors.WrapStr("unable to fetch latest TRC from network", err)
		}
		if fetched.TRC.Version <= decTRC.TRC.Version {
			return nil, nil, serrors.WrapStr("latest TRC from network not newer than local",
				ErrInactive, "net_version", fetched.TRC.Version,
				"local_version", decTRC.TRC.Version, "validity", decTRC.TRC.Validity)
		}
		if !fetched.TRC.Validity.Contains(time.Now()) {
			return nil, nil, serrors.WrapStr("latest TRC from network expired", ErrInactive,
				"version", fetched.TRC.Version, "validity", fetched.TRC.Version)
		}
		return fetched.TRC, fetched.Raw, nil
	}
	return decTRC.TRC, decTRC.Raw, nil
}

// getTRC attempts to grab the TRC from the database; if the TRC is not found,
// it follows up with a network request (if allowed). The options specify
// whether this function is allowed to create new network requests. Parameter
// client contains the node that caused the function to be called, or nil if the
// function was called due to a local feature.
func (p Provider) getTRC(ctx context.Context, id TRCID, opts infra.TRCOpts) (decoded.TRC, error) {
	raw, err := p.DB.GetRawTRC(ctx, id)
	switch {
	case err == nil:
		return decoded.DecodeTRC(raw)
	case !errors.Is(err, ErrNotFound):
		return decoded.TRC{}, serrors.WrapStr("error querying DB for TRC", err)
	case opts.LocalOnly:
		return decoded.TRC{}, serrors.WrapStr("localOnly requested", err)
	default:
		return p.fetchTRC(ctx, id, opts)
	}
}

// fetchTRC fetches a TRC via a network request, if allowed.
func (p Provider) fetchTRC(ctx context.Context, id TRCID,
	opts infra.TRCOpts) (decoded.TRC, error) {

	logger := log.FromCtx(ctx)
	server := opts.Server
	if err := p.Recurser.AllowRecursion(opts.Client); err != nil {
		return decoded.TRC{}, err
	}
	req := TRCReq{
		ISD:     id.ISD,
		Version: id.Version,
	}
	// Choose remote server, if not set.
	if server == nil {
		var err error
		logger.Debug("[TrustStore:Provider] Start choosing remote server for TRC resolution",
			"isd", id.ISD, "addr", server)
		if server, err = p.Router.ChooseServer(ctx, id.ISD); err != nil {
			return decoded.TRC{}, serrors.WrapStr("unable to route TRC request", err)
		}
		logger.Debug("[TrustStore:Provider] Done choosing remote server for TRC resolution",
			"isd", id.ISD, "addr", server)
	}
	decTRC, err := p.Resolver.TRC(ctx, req, server)
	if err != nil {
		return decoded.TRC{}, serrors.WrapStr("unable to fetch signed TRC from network", err,
			"addr", server)
	}
	return decTRC, nil
}

// GetRawChain asks the trust store to return a valid and active certificate
// chain, unless inactive chains are specifically allowed. The optionally
// configured server is queried over the network if the certificate chain is
// not available locally. Otherwise, the default server is queried. How the
// default server is determined differs between implementations.
func (p Provider) GetRawChain(ctx context.Context, id ChainID,
	opts infra.ChainOpts) ([]byte, error) {

	l := metrics.ProviderLabels{Type: metrics.Chain, Trigger: metrics.FromCtx(ctx)}
	chain, err := p.getCheckedChain(ctx, id, opts)
	metrics.Provider.Request(l.WithResult(errToLabel(err))).Inc()
	return chain.Raw, err
}

// GetASKey returns from trust store the public key required to verify signature
// originated from an AS.
func (p Provider) GetASKey(ctx context.Context, id ChainID,
	opts infra.ChainOpts) (scrypto.KeyMeta, error) {

	l := metrics.ProviderLabels{Type: metrics.ASKey, Trigger: metrics.FromCtx(ctx)}
	chain, err := p.getCheckedChain(ctx, id, opts)
	metrics.Provider.Request(l.WithResult(errToLabel(err))).Inc()
	if err != nil {
		return scrypto.KeyMeta{}, err
	}
	return chain.AS.Keys[cert.SigningKey], nil
}

func (p Provider) getCheckedChain(parentCtx context.Context, id ChainID,
	opts infra.ChainOpts) (decoded.Chain, error) {

	span, ctx := opentracing.StartSpanFromContext(parentCtx, "get_checked_chain")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("ia", id.IA)
	span.SetTag("version", id.Version)
	logger := log.FromCtx(ctx)

	chain, err := p.getChain(ctx, id, opts)
	if err != nil {
		return decoded.Chain{}, serrors.WrapStr("unable to get requested certificate chain", err,
			"ia", id.IA, "version", id.Version)
	}
	if opts.AllowInactive {
		return chain, nil
	}
	err = p.issuerActive(ctx, chain, opts.TrustStoreOpts)
	switch {
	case err == nil:
		return chain, nil
	case !errors.Is(err, ErrInactive):
		return decoded.Chain{}, err
	case !id.Version.IsLatest():
		return decoded.Chain{}, err
	case opts.LocalOnly:
		return decoded.Chain{}, err
	default:
		// In case the latest certificate chain is requested, there might be a more
		// recent and active one that is not locally available yet.
		logger.Debug("[TrustStore:Provider] Local latest certificate chain inactive, "+
			"fetching from network", "ia", id.IA)
		fetched, err := p.fetchChain(ctx, id, opts)
		if err != nil {
			return decoded.Chain{},
				serrors.WrapStr("unable to fetch latest certificate chain from network", err)
		}
		if err := p.issuerActive(ctx, fetched, opts.TrustStoreOpts); err != nil {
			return decoded.Chain{},
				serrors.WrapStr("latest certificate chain from network not active", err,
					"chain", fetched)
		}
		return fetched, nil
	}
}

func (p Provider) getChain(ctx context.Context, id ChainID,
	opts infra.ChainOpts) (decoded.Chain, error) {

	raw, err := p.DB.GetRawChain(ctx, id)
	switch {
	case err == nil:
		return decoded.DecodeChain(raw)
	case !errors.Is(err, ErrNotFound):
		return decoded.Chain{}, serrors.WrapStr("error querying DB for certificate chain", err)
	case opts.LocalOnly:
		return decoded.Chain{}, serrors.WrapStr("localOnly requested", err)
	default:
		return p.fetchChain(ctx, id, opts)
	}
}

func (p Provider) issuerActive(ctx context.Context, chain decoded.Chain,
	opts infra.TrustStoreOpts) error {

	if !chain.AS.Validity.Contains(time.Now()) {
		return serrors.WrapStr("AS certificate outside of validity period", ErrInactive,
			"validity", chain.AS.Validity)
	}
	// Ensure that an active TRC is available locally.
	trcOpts := infra.TRCOpts{TrustStoreOpts: opts}
	_, _, err := p.getCheckedTRC(ctx, TRCID{
		ISD: chain.Issuer.Subject.I, Version: scrypto.LatestVer},
		trcOpts)
	if err != nil {
		return serrors.WrapStr("unable to preload latest TRC", err)
	}
	iss, err := p.DB.GetIssuingGrantKeyInfo(ctx, chain.Issuer.Subject,
		chain.Issuer.Issuer.TRCVersion)
	if err != nil {
		return serrors.WrapStr("unable to get issuing key info for issuing TRC", err,
			"version", chain.Issuer.Issuer.TRCVersion)
	}
	latest, err := p.DB.GetIssuingGrantKeyInfo(ctx, chain.Issuer.Subject, scrypto.LatestVer)
	if err != nil {
		return serrors.WrapStr("unable to get issuing key info for latest TRC", err)
	}
	if iss.Version == latest.Version {
		return nil
	}
	if latest.TRC.Base() || graceExpired(latest.TRC) {
		return serrors.WrapStr("different issuing key in latest TRC", ErrInactive,
			"latest_trc_version", latest.TRC.Version,
			"expected", iss.Version, "actual", latest.Version)
	}
	inGrace, err := p.DB.GetIssuingGrantKeyInfo(ctx, chain.Issuer.Subject, latest.TRC.Version-1)
	if err != nil {
		return serrors.WrapStr("unable to get issuing key info for TRC in grace period", err,
			"version", latest.TRC.Version-1)
	}
	if iss.Version != inGrace.Version {
		return serrors.WrapStr("different issuing key in latest TRC", ErrInactive,
			"latest_trc_version", latest.TRC.Version,
			"expected", iss.Version, "actual", latest.Version)
	}
	return nil
}

func (p Provider) fetchChain(ctx context.Context, id ChainID,
	opts infra.ChainOpts) (decoded.Chain, error) {

	logger := log.FromCtx(ctx)
	server := opts.Server
	if err := p.Recurser.AllowRecursion(opts.Client); err != nil {
		return decoded.Chain{}, err
	}
	req := ChainReq{
		IA:      id.IA,
		Version: id.Version,
	}
	// Choose remote server, if not set.
	if server == nil {
		var err error
		logger.Debug("[TrustStore:Provider] Start choosing remote server for certifcate chain "+
			"resolution", "ia", id.IA)
		if server, err = p.Router.ChooseServer(ctx, id.IA.I); err != nil {
			return decoded.Chain{}, serrors.WrapStr("unable to route TRC request", err)
		}
		logger.Debug("[TrustStore:Provider] Done choosing remote server for certifcate chain "+
			"resolution", "ia", id.IA, "addr", server)
	}
	chain, err := p.Resolver.Chain(ctx, req, server)
	if err != nil {
		return decoded.Chain{}, serrors.WrapStr("unable to fetch signed certificate chain "+
			"from network", err, "addr", server)
	}
	return chain, nil
}

func graceExpired(info TRCInfo) bool {
	return time.Now().After(info.Validity.NotBefore.Add(info.GracePeriod))
}
