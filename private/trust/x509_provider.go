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
// from the trust DB.
type X509KeyPairProvider struct {
	IA        addr.IA
	DB        DB
	KeyLoader KeyRing
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

	trcs, _, err := activeTRCs(ctx, p.DB, p.IA.ISD())
	if err != nil {
		return nil, serrors.WrapStr("loading TRCs", err)
	}

	var bestChain []*x509.Certificate
	var bestKey crypto.Signer
	var bestExpiry time.Time
	for _, key := range keys {
		cert, expiry, err := p.bestKeyPair(ctx, trcs, extKeyUsage, key)
		if err != nil {
			return nil, serrors.WrapStr("getting best key pair", err)
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

func (p X509KeyPairProvider) bestKeyPair(
	ctx context.Context,
	signedTRCs []cppki.SignedTRC,
	extKeyUsage x509.ExtKeyUsage,
	signer crypto.Signer,
) ([]*x509.Certificate, time.Time, error) {

	skid, err := cppki.SubjectKeyID(signer.Public())
	if err != nil {
		return nil, time.Time{}, err
	}
	chains, err := p.DB.Chains(ctx, ChainQuery{
		IA:           p.IA,
		SubjectKeyID: skid,
		Date:         time.Now(),
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	trcs := make([]*cppki.TRC, len(signedTRCs))
	for i, signedTRC := range signedTRCs {
		signedTRC := signedTRC
		trcs[i] = &signedTRC.TRC
	}
	chain := bestChainWithKeyUsage(trcs, chains, extKeyUsage)
	if chain == nil {
		return nil, time.Time{}, nil
	}
	return chain, chain[0].NotAfter, nil
}

func bestChainWithKeyUsage(
	trcs []*cppki.TRC,
	chains [][]*x509.Certificate,
	extKeyUsage x509.ExtKeyUsage,
) []*x509.Certificate {

	opts := cppki.VerifyOptions{TRC: trcs}
	var best []*x509.Certificate
	for _, chain := range chains {
		if err := verifyExtendedKeyUsage(chain[0], extKeyUsage); err != nil {
			continue
		}
		if err := cppki.VerifyChain(chain, opts); err != nil {
			continue
		}
		// Use the chain if its validity is longer than any other found so far.
		if len(best) == 0 || chain[0].NotAfter.After(best[0].NotAfter) {
			best = chain
		}
	}
	return best
}
