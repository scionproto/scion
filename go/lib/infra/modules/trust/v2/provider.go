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
	"net"
	"time"

	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrInactive indicates that the requested material is inactive.
var ErrInactive = serrors.New("inactive")

// CryptoProvider provides crypto material. A crypto provider can spawn network
// requests if necessary and permitted.
type CryptoProvider interface {
	// GetTRC asks the trust store to return a valid and active TRC for isd,
	// unless inactive TRCs are specifically allowed. The optionally configured
	// server is queried over the network if the TRC is not available locally.
	// Otherwise, the default server is queried. How the default server is
	// determined differs between implementations.
	GetTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
		opts infra.TRCOpts) (*trc.TRC, error)
	// GetRawTRC behaves the same as GetTRC, except returning the raw signed TRC.
	GetRawTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
		opts infra.TRCOpts, client net.Addr) ([]byte, error)
	// GetRawChain asks the trust store to return a valid and active certificate
	// chain, unless inactive chains are specifically allowed. The optionally
	// configured server is queried over the network if the certificate chain is
	// not available locally. Otherwise, the default server is queried. How the
	// default server is determined differs between implementations.
	GetRawChain(ctx context.Context, ia addr.IA, version scrypto.Version,
		opts infra.ChainOpts, client net.Addr) ([]byte, error)
}

type cryptoProvider struct {
	db       DBRead
	recurser Recurser
	resolver Resolver
	router   Router
}

func (p *cryptoProvider) GetTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
	opts infra.TRCOpts) (*trc.TRC, error) {

	t, _, err := p.getCheckedTRC(ctx, isd, version, opts, nil)
	return t, err
}

func (p *cryptoProvider) GetRawTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
	opts infra.TRCOpts, client net.Addr) ([]byte, error) {

	_, raw, err := p.getCheckedTRC(ctx, isd, version, opts, client)
	return raw, err
}

func (p *cryptoProvider) getCheckedTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
	opts infra.TRCOpts, client net.Addr) (*trc.TRC, []byte, error) {

	decTRC, err := p.getTRC(ctx, isd, version, opts, nil)
	if err != nil {
		return nil, nil, serrors.WrapStr("unable to get requested TRC", err)
	}
	if !opts.AllowInactive {
		info, err := p.db.GetTRCInfo(ctx, isd, scrypto.LatestVer)
		if err != nil {
			return nil, nil, serrors.WrapStr("unable to get latest TRC info", err)
		}
		switch {
		case info.Version > decTRC.TRC.Version+1:
			return nil, nil, serrors.WrapStr("inactivated by latest TRC version", ErrInactive,
				"latest", info.Version)
		case info.Version == decTRC.TRC.Version+1 && graceExpired(info):
			return nil, nil, serrors.WrapStr("grace period has passed", ErrInactive,
				"end", info.Validity.NotBefore.Add(info.GracePeriod), "latest", info.Version)
		case !decTRC.TRC.Validity.Contains(time.Now()):
			if !version.IsLatest() || opts.LocalOnly {
				return nil, nil, serrors.WrapStr("requested TRC expired", ErrInactive,
					"validity", decTRC.TRC.Validity)
			}
			// There might exist a more recent TRC that is not available locally
			// yet. Fetch it if the latest version was requested and recursion
			// is allowed.
			fetched, err := p.fetchTRC(ctx, isd, scrypto.LatestVer, opts, client)
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
	}
	return decTRC.TRC, decTRC.Raw, nil
}

// getTRC attempts to grab the TRC from the database; if the TRC is not found,
// it follows up with a network request (if allowed). The options specify
// whether this function is allowed to create new network requests. Parameter
// client contains the node that caused the function to be called, or nil if the
// function was called due to a local feature.
func (p *cryptoProvider) getTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
	opts infra.TRCOpts, client net.Addr) (decoded.TRC, error) {

	raw, err := p.db.GetRawTRC(ctx, isd, version)
	switch {
	case err == nil:
		return decoded.DecodeTRC(raw)
	case !xerrors.Is(err, ErrNotFound):
		return decoded.TRC{}, serrors.WrapStr("error querying DB for TRC", err)
	case opts.LocalOnly:
		return decoded.TRC{}, serrors.WrapStr("localOnly requested", err)
	default:
		return p.fetchTRC(ctx, isd, version, opts, client)
	}
}

// fetchTRC fetches a TRC via a network request, if allowed.
func (p *cryptoProvider) fetchTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
	opts infra.TRCOpts, client net.Addr) (decoded.TRC, error) {

	server := opts.Server
	if err := p.recurser.AllowRecursion(client); err != nil {
		return decoded.TRC{}, err
	}
	req := TRCReq{
		ISD:     isd,
		Version: version,
	}
	// Choose remote server, if not set.
	if server == nil {
		var err error
		if server, err = p.router.ChooseServer(ctx, isd); err != nil {
			return decoded.TRC{}, serrors.WrapStr("unable to route TRC request", err)
		}
	}
	decTRC, err := p.resolver.TRC(ctx, req, server)
	if err != nil {
		return decoded.TRC{}, serrors.WrapStr("unable to resolve signed TRC from network", err)
	}
	return decTRC, nil
}

func (p *cryptoProvider) GetRawChain(ctx context.Context, ia addr.IA, version scrypto.Version,
	opts infra.ChainOpts, client net.Addr) ([]byte, error) {

	chain, err := p.getChain(ctx, ia, version, opts, client)
	if err != nil {
		return nil, serrors.WrapStr("unable to get requested certificate chain", err)
	}
	if !opts.AllowInactive {
		err := p.issuerActive(ctx, chain, opts.TrustStoreOpts, client)
		switch {
		case err == nil:
		case opts.LocalOnly, !version.IsLatest(), !xerrors.Is(err, ErrInactive):
			return nil, err
		default:
			// There might exist a more recent certificate chain that is not
			// available locally yet.
			fetched, err := p.fetchChain(ctx, ia, scrypto.LatestVer, opts, client)
			if err != nil {
				return nil, serrors.WrapStr("unable to fetch latest certificate chain from network",
					err)
			}
			if err := p.issuerActive(ctx, fetched, opts.TrustStoreOpts, client); err != nil {
				return nil, serrors.WrapStr("latest certificate chain from network not active", err)
			}
			return fetched.Raw, nil
		}
	}
	return chain.Raw, nil
}

func (p *cryptoProvider) issuerActive(ctx context.Context, chain decoded.Chain,
	opts infra.TrustStoreOpts, client net.Addr) error {

	if !chain.AS.Validity.Contains(time.Now()) {
		return serrors.WrapStr("AS certificate outside of validity period", ErrInactive,
			"validity", chain.AS.Validity)
	}
	// Ensure that an active TRC is available locally.
	trcOpts := infra.TRCOpts{TrustStoreOpts: opts}
	_, _, err := p.getCheckedTRC(ctx, chain.Issuer.Subject.I, scrypto.LatestVer, trcOpts, client)
	if err != nil {
		return serrors.WrapStr("unable to preload latest TRC", err)
	}
	iss, err := p.db.GetIssuingKeyInfo(ctx, chain.Issuer.Subject, chain.Issuer.Issuer.TRCVersion)
	if err != nil {
		return serrors.WrapStr("unable to get issuing key info for issuing TRC", err,
			"version", chain.Issuer.Issuer.TRCVersion)
	}
	latest, err := p.db.GetIssuingKeyInfo(ctx, chain.Issuer.Subject, scrypto.LatestVer)
	if err != nil {
		return serrors.WrapStr("unable to get issuing key info for latest TRC", err)
	}
	if iss.Version != latest.Version {
		if latest.TRC.Base() || graceExpired(latest.TRC) {
			return serrors.WrapStr("different issuing key in latest TRC", ErrInactive,
				"latest_trc_version", latest.TRC.Version,
				"expected", iss.Version, "actual", latest.Version)
		}
		inGrace, err := p.db.GetIssuingKeyInfo(ctx, chain.Issuer.Subject, latest.TRC.Version-1)
		if err != nil {
			return serrors.WrapStr("unable to get issuing key info for TRC in grace period", err,
				"version", latest.TRC.Version-1)
		}
		if iss.Version != inGrace.Version {
			return serrors.WrapStr("different issuing key in latest TRC", ErrInactive,
				"latest_trc_version", latest.TRC.Version,
				"expected", iss.Version, "actual", latest.Version)
		}
	}
	return nil
}

func (p *cryptoProvider) getChain(ctx context.Context, ia addr.IA, version scrypto.Version,
	opts infra.ChainOpts, client net.Addr) (decoded.Chain, error) {

	raw, err := p.db.GetRawChain(ctx, ia, version)
	switch {
	case err == nil:
		return decoded.DecodeChain(raw)
	case !xerrors.Is(err, ErrNotFound):
		return decoded.Chain{}, serrors.WrapStr("error querying DB for certificate chain", err)
	case opts.LocalOnly:
		return decoded.Chain{}, serrors.WrapStr("localOnly requested", err)
	default:
		return p.fetchChain(ctx, ia, version, opts, client)
	}
}

func (p *cryptoProvider) fetchChain(ctx context.Context, ia addr.IA, version scrypto.Version,
	opts infra.ChainOpts, client net.Addr) (decoded.Chain, error) {

	server := opts.Server
	if err := p.recurser.AllowRecursion(client); err != nil {
		return decoded.Chain{}, err
	}
	// In case the server is provided, cache-only should be set.
	cacheOnly := server != nil || p.alwaysCacheOnly
	req := ChainReq{
		IA:        ia,
		Version:   version,
		CacheOnly: cacheOnly,
	}
	// Choose remote server, if not set.
	if server == nil {
		var err error
		if server, err = p.router.ChooseServer(ctx, ia.I); err != nil {
			return decoded.Chain{}, serrors.WrapStr("unable to route TRC request", err)
		}
	}
	chain, err := p.resolver.Chain(ctx, req, server)
	if err != nil {
		return decoded.Chain{}, serrors.WrapStr("unable to resolve signed certificate chain"+
			"from network", err)
	}
	return chain, nil
}

func graceExpired(info TRCInfo) bool {
	return time.Now().After(info.Validity.NotBefore.Add(info.GracePeriod))
}
