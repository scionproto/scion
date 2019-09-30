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
	// alwaysCacheOnly forces the cryptoProvider to always send cache-only
	// requests. This should be set in the CS.
	alwaysCacheOnly bool
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

	dec, err := p.getTRC(ctx, isd, version, opts, nil)
	if err != nil {
		return nil, nil, serrors.WrapStr("unable to get requested TRC", err)
	}
	if !opts.AllowInactive {
		info, err := p.db.GetTRCInfo(ctx, isd, scrypto.Version(scrypto.LatestVer))
		if err != nil {
			return nil, nil, serrors.WrapStr("unable to get latest TRC info", err)
		}
		switch {
		case info.Version > dec.TRC.Version+1:
			return nil, nil, serrors.WrapStr("inactivated by latest TRC version", ErrInactive,
				"latest", info.Version)
		case info.Version == dec.TRC.Version+1 && graceExpired(info):
			return nil, nil, serrors.WrapStr("grace period has passed", ErrInactive,
				"end", info.Validity.NotBefore.Add(info.GracePeriod), "latest", info.Version)
		case !dec.TRC.Validity.Contains(time.Now()):
			if version != scrypto.Version(scrypto.LatestVer) || opts.LocalOnly {
				return nil, nil, serrors.WrapStr("requested TRC expired", ErrInactive,
					"validity", dec.TRC.Validity)
			}
			// There might exist a more recent TRC that is not available locally
			// yet. Fetch it if the latest version was requested and recursion
			// is allowed.
			fetched, err := p.fetchTRC(ctx, isd, scrypto.Version(scrypto.LatestVer), opts, client)
			if err != nil {
				return nil, nil, serrors.WrapStr("unable to fetch latest TRC from network", err)
			}
			if fetched.TRC.Version <= dec.TRC.Version {
				return nil, nil, serrors.WrapStr("latest TRC from network not newer than local",
					ErrInactive, "net_version", fetched.TRC.Version,
					"local_version", dec.TRC.Version, "validity", dec.TRC.Validity)
			}
			if !fetched.TRC.Validity.Contains(time.Now()) {
				return nil, nil, serrors.WrapStr("latest TRC from network expired", ErrInactive,
					"version", fetched.TRC.Version, "validity", fetched.TRC.Version)
			}
			return fetched.TRC, fetched.Raw, nil
		}
	}
	return dec.TRC, dec.Raw, nil
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
	// In case the server is provided, cache-only should be set.
	cacheOnly := server != nil || p.alwaysCacheOnly
	req := TRCReq{
		ISD:       isd,
		Version:   version,
		CacheOnly: cacheOnly,
	}
	// Choose remote server, if not set.
	if server == nil {
		var err error
		if server, err = p.router.ChooseServer(ctx, isd); err != nil {
			return decoded.TRC{}, serrors.WrapStr("unable to route TRC request", err)
		}
	}
	dec, err := p.resolver.TRC(ctx, req, server)
	if err != nil {
		return decoded.TRC{}, serrors.WrapStr("unable to resolve signed TRC from network", err)
	}
	return dec, nil
}

func (p *cryptoProvider) GetRawChain(ctx context.Context, ia addr.IA, version scrypto.Version,
	opts infra.ChainOpts, client net.Addr) ([]byte, error) {

	// TODO(roosd): implement.
	return nil, serrors.New("not implemented")
}

func graceExpired(info TRCInfo) bool {
	return time.Now().After(info.Validity.NotBefore.Add(info.GracePeriod))
}
