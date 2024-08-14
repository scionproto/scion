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

package renewal

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
)

var (
	errRootCert        = serrors.New("root certificate")
	errOutsideValidity = serrors.New("outside validity")
)

type Metrics struct {
	// CAActive describes whether the CA signer is active and can sign
	// certificate chains.
	CAActive metrics.Gauge
	// CASigners tracks the number of generated CA signers that sign certificate
	// chains.
	CASigners func(string) metrics.Counter
	// SignedChains tracks the number of certificate chains signed, labeled by
	// the status of the signing.
	SignedChains func(string) metrics.Counter
	// LastGeneratedCA exports the last time a signer for creating AS
	// certificates was successfully generated.
	LastGeneratedCA metrics.Gauge
	// ExpirationCA exports the expiration time of the current CA signer.
	ExpirationCA metrics.Gauge
}

// PolicyGen generates a new CA policy.
type PolicyGen interface {
	Generate(context.Context) (cppki.CAPolicy, error)
}

// ChainBuilder creates a certificate chain with the generated policy.
type ChainBuilder struct {
	PolicyGen    PolicyGen
	SignedChains func(string) metrics.Counter
}

// CreateChain creates a certificate chain with the latest available CA policy.
func (c ChainBuilder) CreateChain(ctx context.Context,
	csr *x509.CertificateRequest) ([]*x509.Certificate, error) {

	policy, err := c.PolicyGen.Generate(ctx)
	if err != nil {
		c.incSignedChains("err_inactive")
		return nil, err
	}
	chain, err := policy.CreateChain(csr)
	if err != nil {
		c.incSignedChains("err_internal")
		return nil, err
	}
	c.incSignedChains("ok_success")
	return chain, nil
}

func (c ChainBuilder) incSignedChains(result string) {
	if c.SignedChains != nil {
		metrics.CounterInc(c.SignedChains(result))
	}
}

// CachingPolicyGen is a PolicyGen that can cache the previously generated
// CASigner for some time.
type CachingPolicyGen struct {
	PolicyGen PolicyGen
	Interval  time.Duration

	CAActive        metrics.Gauge
	LastGeneratedCA metrics.Gauge
	ExpirationCA    metrics.Gauge

	mtx     sync.Mutex
	lastGen time.Time
	cached  cppki.CAPolicy
	ok      bool
}

// Generate generates a CAPolicy using the PolicyGen or returns the cached
// CAPolicy.
func (s *CachingPolicyGen) Generate(ctx context.Context) (cppki.CAPolicy, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	now := time.Now()
	if now.Sub(s.lastGen) < s.Interval {
		if !s.ok {
			return cppki.CAPolicy{}, serrors.New("no CA policy available, " +
				"reload interval has not passed")
		}
		return s.cached, nil
	}
	s.lastGen = now
	policy, err := s.PolicyGen.Generate(ctx)
	if err != nil {
		s.ok = false
		log.FromCtx(ctx).Info("Failed to generate a new CA policy, "+
			"AS certificate signing not possible", "err", err)
		metrics.GaugeSet(s.CAActive, 0)
		return cppki.CAPolicy{}, err
	}
	if !s.cached.Equal(policy) {
		log.FromCtx(ctx).Info("Generated new CA policy",
			"subject_key_id", fmt.Sprintf("%x", policy.Certificate.SubjectKeyId),
			"expiration", policy.Certificate.NotAfter,
		)
	}
	s.cached, s.ok = policy, true

	metrics.GaugeSet(s.CAActive, 1)
	metrics.GaugeSetCurrentTime(s.LastGeneratedCA)
	metrics.GaugeSetTimestamp(s.ExpirationCA, policy.Certificate.NotAfter)
	return s.cached, nil
}

// CACertProvider provides verifiable CA certificates.
type CACertProvider interface {
	// CACerts returns a list of CA certificates that are verifiable with an
	// active TRC.
	CACerts(ctx context.Context) ([]*x509.Certificate, error)
}

// LoadingPolicyGen generates a CAPolicy from the keys and certificates
// available on the file system.
type LoadingPolicyGen struct {
	Validity     time.Duration
	KeyRing      trust.KeyRing
	CertProvider CACertProvider

	CASigners func(string) metrics.Counter

	// ForceECDSAWithSHA512 forces the CA policy to use ECDSAWithSHA512 as the
	// signature algorithm for signing the issued certificate. This field
	// forces the old behavior extending the acceptable signature algorithms
	// in https://github.com/scionproto/scion/commit/df8565dc97cb6ef7c7925c26f23f3e9954ab2a97.
	//
	// Experimental: This field is experimental and will be subject to change.
	ForceECDSAWithSHA512 bool
}

// Generate fetches private keys from the key ring and searches active CA
// certificates that authenticate the corresponding public key. The returned
// policy uses the private which is backed by the CA certificate with the
// highest expiration time.
func (l LoadingPolicyGen) Generate(ctx context.Context) (cppki.CAPolicy, error) {
	keys, err := l.KeyRing.PrivateKeys(ctx)
	if err != nil {
		l.incCASigner("err_key")
		return cppki.CAPolicy{}, err
	}
	if len(keys) == 0 {
		l.incCASigner("err_key")
		return cppki.CAPolicy{}, serrors.New("no private key found")
	}

	certs, err := l.CertProvider.CACerts(ctx)
	if err != nil {
		l.incCASigner("err_certs")
		return cppki.CAPolicy{}, serrors.Wrap("loading CA certificates", err)
	}
	if len(certs) == 0 {
		l.incCASigner("err_certs")
		return cppki.CAPolicy{}, serrors.New("no CA certificate found")
	}

	// Search the private key that has a certificate that expires the latest.
	var bestCert *x509.Certificate
	var bestKey crypto.Signer
	for _, key := range keys {
		skid, err := cppki.SubjectKeyID(key.Public())
		if err != nil {
			continue
		}
		for _, cert := range certs {
			if !bytes.Equal(skid, cert.SubjectKeyId) {
				continue
			}
			if bestCert == nil || cert.NotAfter.After(bestCert.NotAfter) {
				bestCert, bestKey = cert, key
			}
		}
	}
	if bestCert == nil {
		l.incCASigner("err_not_found")
		return cppki.CAPolicy{}, serrors.New("no CA certificate found",
			"num_private_keys", len(keys))
	}
	l.incCASigner("ok_success")
	return cppki.CAPolicy{
		Validity:             l.Validity,
		Certificate:          bestCert,
		Signer:               bestKey,
		ForceECDSAWithSHA512: l.ForceECDSAWithSHA512,
	}, nil
}

func (l LoadingPolicyGen) incCASigner(result string) {
	if l.CASigners != nil {
		metrics.CounterInc(l.CASigners(result))
	}
}

// CACertLoader loads CA certificates from disk.
type CACertLoader struct {
	IA  addr.IA
	Dir string
	DB  trust.DB
}

// CACerts returns a list of CA certificates from disk that are verifiable with
// an active TRC.
func (l CACertLoader) CACerts(ctx context.Context) ([]*x509.Certificate, error) {
	if _, err := os.Stat(l.Dir); err != nil {
		return nil, serrors.Wrap("stating directory", err, "dir", l.Dir)
	}
	files, err := filepath.Glob(fmt.Sprintf("%s/*.crt", l.Dir))
	if err != nil {
		return nil, serrors.Wrap("searching for certificates", err, "dir", l.Dir)
	}

	trcs, err := activeTRCs(ctx, l.DB, l.IA.ISD())
	if err != nil {
		return nil, serrors.Wrap("looking for active TRCs", err, "isd", l.IA.ISD())
	}
	rootPool := x509.NewCertPool()
	for _, trc := range trcs {
		certs, err := trc.TRC.RootCerts()
		if err != nil {
			return nil, serrors.Wrap("extracting root certs", err, "trc", trc.TRC.ID)
		}
		for _, cert := range certs {
			rootPool.AddCert(cert)
		}
	}
	logger := log.FromCtx(ctx)
	opts := x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	var certs []*x509.Certificate
	var loaded []string
	for _, f := range files {
		cert, err := l.validateCACert(f, opts)
		if err != nil {
			if errors.Is(err, errRootCert) {
				logger.Debug("Ignoring non-CA certificate", "file", f, "reason", err)
				continue
			}
			if errors.Is(err, errOutsideValidity) {
				logger.Debug("Ignoring CA certificate outside validity", "file", f)
				continue
			}
			logger.Info("Ignoring non-CA certificate", "file", f, "reason", err)
			continue
		}
		loaded = append(loaded, f)
		certs = append(certs, cert)
	}
	log.FromCtx(ctx).Debug("CA certificates loaded", "files", loaded)
	return certs, nil
}

func (l CACertLoader) validateCACert(f string, opts x509.VerifyOptions) (*x509.Certificate, error) {
	chain, err := cppki.ReadPEMCerts(f)
	if err != nil {
		return nil, err
	}
	t, err := cppki.ValidateCert(chain[0])
	if err != nil {
		return nil, err
	}
	if t == cppki.Root {
		return nil, errRootCert
	}
	if t != cppki.CA {
		return nil, serrors.New("wrong type", "actual", t)
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return nil, err
	}
	if !l.IA.Equal(ia) {
		return nil, serrors.New("certificate for other ISD-AS", "isd_as", ia)
	}
	validity := cppki.Validity{NotBefore: chain[0].NotBefore, NotAfter: chain[0].NotAfter}
	if !validity.Contains(time.Now()) {
		return nil, errOutsideValidity
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return nil, err
	}
	return chain[0], nil
}

func activeTRCs(ctx context.Context, db trust.DB, isd addr.ISD) ([]cppki.SignedTRC, error) {
	errNotFound := serrors.New("not found")
	trc, err := db.SignedTRC(ctx, cppki.TRCID{
		ISD:    isd,
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil {
		return nil, err
	}
	if trc.IsZero() {
		return nil, errNotFound
	}
	if !trc.TRC.Validity.Contains(time.Now()) {
		return nil, serrors.New("no active TRC found in database")
	}
	if !trc.TRC.InGracePeriod(time.Now()) {
		return []cppki.SignedTRC{trc}, nil
	}
	grace, err := db.SignedTRC(ctx, cppki.TRCID{
		ISD:    isd,
		Base:   trc.TRC.ID.Base,
		Serial: trc.TRC.ID.Serial - 1,
	})
	if err != nil {
		return nil, err
	}
	if grace.IsZero() {
		return nil, errNotFound
	}
	return []cppki.SignedTRC{trc, grace}, nil
}
