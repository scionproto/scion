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

package control

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"time"

	cstrust "github.com/scionproto/scion/control/trust"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/ca/renewal"
	"github.com/scionproto/scion/private/trust"
)

// LoadTrustMaterial loads the trust material from disk. The logger must not be nil.
func LoadTrustMaterial(ctx context.Context, configDir string, db trust.DB) error {
	logger := log.FromCtx(ctx)
	certsDir := filepath.Join(configDir, "certs")
	loaded, err := trust.LoadTRCs(context.Background(), certsDir, db)
	if err != nil {
		return serrors.Wrap("loading TRCs from disk", err)
	}
	logger.Info("TRCs loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		if errors.Is(r, trust.ErrAlreadyExists) {
			logger.Debug("Ignoring existing TRC", "file", f)
			continue
		}
		logger.Info("Ignoring non-TRC", "file", f, "reason", r)
	}
	localCertsDir := filepath.Join(configDir, "crypto/as")
	loaded, err = trust.LoadChains(context.Background(), localCertsDir, db)
	if err != nil {
		return serrors.Wrap("loading certificate chains from disk", err)
	}
	logger.Info("Certificate chains loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		if errors.Is(r, trust.ErrAlreadyExists) {
			logger.Debug("Ignoring existing certificate chain", "file", f)
			continue
		}
		if errors.Is(r, trust.ErrOutsideValidity) {
			logger.Debug("Ignoring certificate chain outside validity", "file", f)
			continue
		}
		logger.Info("Ignoring non-certificate chain", "file", f, "reason", r)
	}
	return nil
}

func NewTLSCertificateLoader(
	ia addr.IA,
	extKeyUsage x509.ExtKeyUsage,
	db trust.DB,
	cfgDir string,
) cstrust.TLSCertificateLoader {

	return cstrust.TLSCertificateLoader{
		SignerGen: newCachingSignerGen(ia, extKeyUsage, db, cfgDir),
	}
}

// NewSigner creates a renewing signer backed by a certificate chain.
func NewSigner(ia addr.IA, db trust.DB, cfgDir string) cstrust.RenewingSigner {
	signer := cstrust.RenewingSigner{
		SignerGen: newCachingSignerGen(ia, x509.ExtKeyUsageAny, db, cfgDir),
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	if _, err := signer.SignerGen.Generate(ctx); err != nil {
		log.Debug("Initial signer generation failed", "err", err)
	}
	return signer
}

// newCachingSignerGen creates a caching signer generator (i.e. a key/cert loader).
// If key usage is specified (not ExtKeyUsageAny), only signers with matching
// certificates will be returned.
func newCachingSignerGen(
	ia addr.IA,
	extKeyUsage x509.ExtKeyUsage,
	db trust.DB,
	cfgDir string,
) *cstrust.CachingSignerGen {

	gen := trust.SignerGen{
		IA: ia,
		DB: &cstrust.CryptoLoader{
			Dir:     filepath.Join(cfgDir, "crypto/as"),
			TRCDirs: []string{filepath.Join(cfgDir, "certs")},
			DB:      db,
		},
		KeyRing: cstrust.LoadingRing{
			Dir: filepath.Join(cfgDir, "crypto/as"),
		},
		ExtKeyUsage: extKeyUsage,
	}
	return &cstrust.CachingSignerGen{
		SignerGen: gen,
		Interval:  5 * time.Second,
	}
}

type ChainBuilderConfig struct {
	IA          addr.IA
	DB          trust.DB
	MaxValidity time.Duration
	ConfigDir   string
	Metrics     renewal.Metrics

	// ForceECDSAWithSHA512 forces the CA policy to use ECDSAWithSHA512 as the
	// signature algorithm for signing the issued certificate. This field
	// forces the old behavior extending the acceptable signature algorithms
	// in https://github.com/scionproto/scion/commit/df8565dc97cb6ef7c7925c26f23f3e9954ab2a97.
	//
	// Experimental: This field is experimental and will be subject to change.
	ForceECDSAWithSHA512 bool
}

// NewChainBuilder creates a renewing chain builder.
func NewChainBuilder(cfg ChainBuilderConfig) renewal.ChainBuilder {
	return renewal.ChainBuilder{
		PolicyGen: &renewal.CachingPolicyGen{
			PolicyGen: renewal.LoadingPolicyGen{
				Validity: cfg.MaxValidity,
				CertProvider: renewal.CACertLoader{
					IA:  cfg.IA,
					DB:  cfg.DB,
					Dir: filepath.Join(cfg.ConfigDir, "crypto/ca"),
				},
				KeyRing: cstrust.LoadingRing{
					Dir: filepath.Join(cfg.ConfigDir, "crypto/ca"),
				},
				ForceECDSAWithSHA512: cfg.ForceECDSAWithSHA512,
				CASigners:            cfg.Metrics.CASigners,
			},
			CAActive:        cfg.Metrics.CAActive,
			LastGeneratedCA: cfg.Metrics.LastGeneratedCA,
			ExpirationCA:    cfg.Metrics.ExpirationCA,
		},
		SignedChains: cfg.Metrics.SignedChains,
	}
}
