// Copyright 2024 Anapaya Systems
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

package beacon

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/patrickmn/go-cache"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	infra "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/trust"
)

type ChainProvider interface {
	GetChains(context.Context, trust.ChainQuery, ...trust.Option) ([][]*x509.Certificate, error)
}

const (
	defaultCacheHitExpiration  = 10 * time.Minute
	defaultCacheMissExpiration = 30 * time.Second
)

var _ infra.Verifier = (chainChecker{})

// chainChecker checks that the certificate chain is available locally. This is used
// to ensure we do not propagate beacons that are not verifiable.
type chainChecker struct {
	BoundValidity cppki.Validity
	Engine        ChainProvider

	Cache *cache.Cache
}

func (v chainChecker) WithValidity(val cppki.Validity) infra.Verifier {
	v.BoundValidity = val
	return v
}

func (v chainChecker) Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	hdr, err := signed.ExtractUnverifiedHeader(signedMsg)
	if err != nil {
		return nil, err
	}

	var keyID cppb.VerificationKeyID
	if err := proto.Unmarshal(hdr.VerificationKeyID, &keyID); err != nil {
		return nil, serrors.Wrap("parsing verification key ID", err)
	}
	if len(keyID.SubjectKeyId) == 0 {
		return nil, serrors.Wrap("subject key ID must be set", err)
	}
	ia := addr.IA(keyID.IsdAs)
	if ia.IsWildcard() {
		return nil, serrors.New("ISD-AS must not contain wildcard", "isd_as", ia)
	}
	if v.Engine == nil {
		return nil, serrors.New("nil engine that provides cert chains")
	}
	query := trust.ChainQuery{
		IA:           ia,
		SubjectKeyID: keyID.SubjectKeyId,
		Validity:     v.BoundValidity,
	}
	if err := v.checkChains(ctx, query); err != nil {
		return nil, serrors.Wrap("getting chains", err,
			"query.isd_as", query.IA,
			"query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID),
			"query.validity", query.Validity.String(),
		)
	}
	return nil, nil
}

func (v chainChecker) checkChains(ctx context.Context, q trust.ChainQuery) error {
	key := fmt.Sprintf("chain-%s-%x", q.IA, q.SubjectKeyID)

	cachedChains, ok := v.getChainsCached(key)
	if ok {
		if len(cachedChains) == 0 {
			return serrors.New("cached certificate chains are empty")
		}

		var validChains int
		for _, chain := range cachedChains {
			if len(chain) == 0 {
				continue // This should never happen.
			}
			chainValidity := cppki.Validity{
				NotBefore: chain[0].NotBefore,
				NotAfter:  chain[0].NotAfter,
			}
			if v.BoundValidity != (cppki.Validity{}) && !chainValidity.Covers(v.BoundValidity) {
				continue
			}
			validChains++
		}
		if validChains == 0 {
			// Remove the invalid chains from the cache. This is a rare case if
			// we have previously cached chains, but they have now expired.
			// After the cache is cleared here, we will attempt to fetch and
			// cache the empty result, thus, not hitting this code path again.
			v.Cache.Delete(key)
			return serrors.New("chached certificate chains do not cover required validity")
		}
		return nil
	}

	chains, err := v.Engine.GetChains(ctx, q)
	if err != nil {
		return err
	}
	v.cacheChains(key, chains, v.cacheExpiration(chains))
	if len(chains) == 0 {
		return serrors.New("no certificate chains found")
	}
	return nil
}

func (v chainChecker) getChainsCached(key string) ([][]*x509.Certificate, bool) {
	chain, ok := v.Cache.Get(key)
	if !ok {
		return nil, false
	}
	return chain.([][]*x509.Certificate), true
}

func (v chainChecker) cacheChains(key string, chain [][]*x509.Certificate, d time.Duration) {
	v.Cache.Set(key, chain, d)
}

func (v chainChecker) cacheExpiration(chains [][]*x509.Certificate) time.Duration {
	// In case of a miss, we cache the result for a short time. This allows us to
	// learn about new chains more quickly.
	if len(chains) == 0 {
		return defaultCacheMissExpiration
	}
	return defaultCacheHitExpiration
}

func (v chainChecker) WithServer(server net.Addr) infra.Verifier { return v }
func (v chainChecker) WithIA(ia addr.IA) infra.Verifier          { return v }
