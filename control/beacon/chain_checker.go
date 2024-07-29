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
	"math/rand"
	"net"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	infra "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/trust"
	"google.golang.org/protobuf/proto"
)

type ChainProvider interface {
	GetChains(context.Context, trust.ChainQuery, ...trust.Option) ([][]*x509.Certificate, error)
}

const defaultCacheExpiration = 10 * time.Minute

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
		return nil, serrors.WrapStr("parsing verification key ID", err)
	}
	if len(keyID.SubjectKeyId) == 0 {
		return nil, serrors.WrapStr("subject key ID must be set", err)
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
	if _, err := v.getChains(ctx, query); err != nil {
		return nil, serrors.WrapStr("getting chains", err,
			"query.isd_as", query.IA,
			"query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID),
			"query.validity", query.Validity.String(),
		)
	}
	return nil, nil
}

func (v chainChecker) getChains(
	ctx context.Context,
	q trust.ChainQuery,
) ([][]*x509.Certificate, error) {
	key := fmt.Sprintf("chain-%s-%x", q.IA, q.SubjectKeyID)

	cachedChains, ok := v.getChainsCached(key)
	if ok {
		return cachedChains, nil
	}

	chains, err := v.Engine.GetChains(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(chains) != 0 {
		v.cacheChains(key, chains, v.cacheExpiration(chains))
	}
	return chains, nil
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
	dur := defaultCacheExpiration
	validity := time.Duration(rand.Int63n(int64(dur-(dur/2))) + int64(dur/2))
	expiration := time.Now().Add(validity)
	for _, chain := range chains {
		if notAfter := chain[0].NotAfter; notAfter.Before(expiration) {
			expiration = notAfter
		}
	}
	return time.Until(expiration)
}

func (v chainChecker) WithServer(server net.Addr) infra.Verifier { return v }
func (v chainChecker) WithIA(ia addr.IA) infra.Verifier          { return v }
