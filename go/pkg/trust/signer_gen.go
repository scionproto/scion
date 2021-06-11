// Copyright 2020 Anapaya Systems
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
	"crypto/x509"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

// KeyRing provides private keys.
type KeyRing interface {
	PrivateKeys(ctx context.Context) ([]crypto.Signer, error)
}

// SignerGen generates signers from the keys available in key dir.
type SignerGen struct {
	IA      addr.IA
	KeyRing KeyRing
	DB      DB // FIXME(roosd): Eventually this should use a crypto provider
}

// Generate fetches private keys from the key ring and searches active
// certificate chains that authenticate the corresponding public key. The
// returned signer uses the private key which is backed by the certificate chain
// with the highest expiration time.
func (s SignerGen) Generate(ctx context.Context) (Signer, error) {
	l := metrics.SignerLabels{}
	keys, err := s.KeyRing.PrivateKeys(ctx)
	if err != nil {
		metrics.Signer.Generate(l.WithResult(metrics.ErrKey)).Inc()
		return Signer{}, err
	}
	if len(keys) == 0 {
		metrics.Signer.Generate(l.WithResult(metrics.ErrKey)).Inc()
		return Signer{}, serrors.New("no private key found")
	}

	trcs, res, err := activeTRCs(ctx, s.DB, s.IA.I)
	if err != nil {
		metrics.Signer.Generate(l.WithResult(res)).Inc()
		return Signer{}, serrors.WrapStr("loading TRC", err)
	}

	// Search the private key that has a certificate that expires the latest.
	var best *Signer
	for _, key := range keys {
		signer, err := s.bestForKey(ctx, key, trcs)
		if err != nil {
			metrics.Signer.Generate(l.WithResult(metrics.ErrDB)).Inc()
			return Signer{}, err
		}
		if signer == nil {
			continue
		}
		if best != nil && signer.Expiration.Before(best.Expiration) {
			continue
		}
		best = signer
	}
	if best == nil {
		metrics.Signer.Generate(l.WithResult(metrics.ErrNotFound)).Inc()
		return Signer{}, serrors.New("no certificate found", "num_private_keys", len(keys))
	}
	metrics.Signer.Generate(l.WithResult(metrics.Success)).Inc()
	return *best, nil
}

func (s *SignerGen) bestForKey(ctx context.Context, key crypto.Signer,
	trcs []cppki.SignedTRC) (*Signer, error) {
	// FIXME(roosd): We currently take the sha1 sum of the public key.
	// The final implementation needs to be smarter than that, but this
	// requires a proper design that also considers certificate renewal.
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		// Do not return an error. We might still find a key with a matching
		// certificate later on.
		return nil, nil
	}
	algo, err := signed.SelectSignatureAlgorithm(key.Public())
	if err != nil {
		return nil, err
	}
	chains, err := s.DB.Chains(ctx, ChainQuery{
		IA:           s.IA,
		SubjectKeyID: skid,
		Date:         time.Now(),
	})
	if err != nil {
		// TODO	metrics.Signer.Generate(l.WithResult(metrics.ErrDB)).Inc()
		return nil, err
	}
	chain := bestChain(&trcs[0].TRC, chains)
	if chain == nil && len(trcs) == 1 {
		return nil, nil
	}
	var inGrace bool
	// Attempt to find a chain that is verifiable only in grace period. If we
	// have not found a chain yet.
	if chain == nil && len(trcs) == 2 {
		chain = bestChain(&trcs[1].TRC, chains)
		if chain == nil {
			return nil, nil
		}
		inGrace = true
	}
	expiry := min(chain[0].NotAfter, trcs[0].TRC.Validity.NotAfter)
	if inGrace {
		expiry = min(chain[0].NotAfter, trcs[0].TRC.GracePeriodEnd())
	}
	return &Signer{
		PrivateKey:   key,
		Algorithm:    algo,
		IA:           s.IA,
		TRCID:        trcs[0].TRC.ID,
		Subject:      chain[0].Subject,
		Chain:        chain,
		SubjectKeyID: chain[0].SubjectKeyId,
		Expiration:   expiry,
		ChainValidity: cppki.Validity{
			NotBefore: chain[0].NotBefore,
			NotAfter:  chain[0].NotAfter,
		},
		InGrace: inGrace,
	}, nil
}

func bestChain(trc *cppki.TRC, chains [][]*x509.Certificate) []*x509.Certificate {
	opts := cppki.VerifyOptions{TRC: []*cppki.TRC{trc}}
	var best []*x509.Certificate
	for _, chain := range chains {
		if err := cppki.VerifyChain(chain, opts); err != nil {
			continue
		}
		if len(best) > 0 && chain[0].NotAfter.Before(best[0].NotAfter) {
			continue
		}
		best = chain
	}
	return best
}

func min(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
