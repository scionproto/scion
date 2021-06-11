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

package cs

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	"github.com/scionproto/scion/go/pkg/trust"
)

// LoadTrustMaterial loads the trust material from disk. The logger must not be nil.
func LoadTrustMaterial(configDir string, db trust.DB, logger log.Logger) error {
	certsDir := filepath.Join(configDir, "certs")
	loaded, err := trust.LoadTRCs(context.Background(), certsDir, db)
	if err != nil {
		return serrors.WrapStr("loading TRCs from disk", err)
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
		return serrors.WrapStr("loading certificate chains from disk", err)
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

// NewSigner creates a renewing signer backed by a certificate chain..
func NewSigner(ia addr.IA, db trust.DB, cfgDir string) (cstrust.RenewingSigner, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	gen := trust.SignerGen{
		IA: ia,
		DB: cstrust.CryptoLoader{
			Dir: filepath.Join(cfgDir, "crypto/as"),
			DB:  db,
		},
		KeyRing: cstrust.LoadingRing{
			Dir: filepath.Join(cfgDir, "crypto/as"),
		},
	}
	cachingGen := &cstrust.CachingSignerGen{
		SignerGen: gen,
		Interval:  5 * time.Second,
	}
	if _, err := cachingGen.Generate(ctx); err != nil {
		return cstrust.RenewingSigner{}, err
	}
	return cstrust.RenewingSigner{
		SignerGen: cachingGen,
	}, nil
}

type ChainBuilderConfig struct {
	IA          addr.IA
	DB          trust.DB
	MaxValidity time.Duration
	ConfigDir   string

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
			},
		},
	}
}
