// Copyright 2022 ETH Zurich
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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// X509KeyPairProvider loads x509 certificate/key pairs
type X509KeyPairProvider struct {
	IA          addr.IA
	ChainLoader DB
	KeyLoader   KeyRing
}

var _ X509KeyPairLoader = (*X509KeyPairProvider)(nil)

// LoadServerKeyPair loads a valid tls.Certificate with id-kp-serverAuth.
// See: https://docs.scion.org/en/latest/cryptography/certificates.html#extended-key-usage-extension
func (p X509KeyPairProvider) LoadServerKeyPair(ctx context.Context) (*tls.Certificate, error) {
	return p.loadX509KeyPair(ctx, x509.ExtKeyUsageServerAuth)
}

// LoadClientKeyPair loads a valid tls.Certificate with id-kp-clientAuth.
// See: https://docs.scion.org/en/latest/cryptography/certificates.html#extended-key-usage-extension
func (p X509KeyPairProvider) LoadClientKeyPair(ctx context.Context) (*tls.Certificate, error) {
	return p.loadX509KeyPair(ctx, x509.ExtKeyUsageServerAuth)
}

func (p X509KeyPairProvider) loadX509KeyPair(
	ctx context.Context,
	extKeyUsage x509.ExtKeyUsage,
) (*tls.Certificate, error) {

	keys, err := p.KeyLoader.PrivateKeys(ctx)
	if err != nil {
		return nil, serrors.WrapStr("getting keys", err)
	}
	if len(keys) == 0 {
		return nil, serrors.New("no private key found")
	}

	var bestChain []*x509.Certificate
	var bestKey crypto.Signer
	var bestExpiry time.Time
	for _, key := range keys {
		skid, err := cppki.SubjectKeyID(key.Public())
		if err != nil {
			return nil, serrors.WrapStr("computing subject key id", err)
		}
		cert, expiry, err := p.bestChainForKey(ctx, skid, extKeyUsage)
		if err != nil {
			return nil, serrors.WrapStr("loading certificate chain for key", err)
		}
		if cert == nil {
			continue
		}
		if bestChain != nil && bestExpiry.After(expiry) {
			continue
		}
		bestChain = cert
		bestKey = key
		bestExpiry = expiry
	}
	if bestChain == nil {
		return nil, serrors.New("no certificate found")
	}
	certificate := make([][]byte, len(bestChain))
	for i := range bestChain {
		certificate[i] = bestChain[i].Raw
	}
	return &tls.Certificate{
		Certificate: certificate,
		PrivateKey:  bestKey,
		Leaf:        bestChain[0],
	}, nil
}

// bestChainForKey returns the certificate chain with latest expiry matching
// the given subject key ID and key usage.
func (p X509KeyPairProvider) bestChainForKey(
	ctx context.Context,
	skid []byte,
	extKeyUsage x509.ExtKeyUsage,
) ([]*x509.Certificate, time.Time, error) {

	chains, err := p.ChainLoader.Chains(ctx, ChainQuery{
		IA:           p.IA,
		SubjectKeyID: skid,
		Date:         time.Now(),
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	chain := bestChainWithKeyUsage(chains, extKeyUsage)
	if chain == nil {
		return nil, time.Time{}, nil
	}
	return chain, chain[0].NotAfter, nil
}

func bestChainWithKeyUsage(
	chains [][]*x509.Certificate,
	extKeyUsage x509.ExtKeyUsage,
) []*x509.Certificate {

	var best []*x509.Certificate
	for _, chain := range chains {
		if err := verifyExtendedKeyUsage(chain[0], extKeyUsage); err != nil {
			continue
		}
		// Use the chain if its validity is longer than any other found so far.
		if len(best) == 0 || chain[0].NotAfter.After(best[0].NotAfter) {
			best = chain
		}
	}
	return best
}
