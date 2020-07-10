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
	"path/filepath"
	"time"

	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/cs/segreq"
	"github.com/scionproto/scion/go/cs/segutil"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/compat"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
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
		logger.Info("Ignoring non-TRC", "file", f, "reason", r)
	}
	localCertsDir := filepath.Join(configDir, "crypto/as")
	loaded, err = trust.LoadChains(context.Background(), localCertsDir, db)
	if err != nil {
		return serrors.WrapStr("loading certificate chains from disk", err)
	}
	logger.Info("Certificate chains loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		logger.Info("Ignoring non-certificate chain", "file", f, "reason", r)
	}
	return nil
}

// TrustProviderConfig configures how the trust provider is created.
type TrustProviderConfig struct {
	IA       addr.IA
	PathDB   pathdb.PathDB
	RevCache revcache.RevCache
	TrustDB  trust.DB
	RPC      interface {
		trust.RPC
		segfetcher.RequestAPI
	}
	Pather        segreq.Pather
	Inspector     trust.Inspector
	Provider      topology.Provider
	DstProvider   segfetcher.DstProvider
	QueryInterval time.Duration
	Core          bool
	HeaderV2      bool
}

// NewTrustProvider creates a trust material provider that uses paths from the path storage.
func NewTrustProvider(cfg TrustProviderConfig) trust.FetchingProvider {
	trustRouter := &segutil.Router{
		Pather: segfetcher.Pather{
			PathDB:       cfg.PathDB,
			RevCache:     cfg.RevCache,
			TopoProvider: cfg.Provider,
			HeaderV2:     cfg.HeaderV2,
			// Fetcher needs to be initialized with a provider.
		},
	}
	provider := trust.FetchingProvider{
		DB: cfg.TrustDB,
		Fetcher: trust.DefaultFetcher{
			RPC: cfg.RPC,
			IA:  cfg.IA,
		},
		Recurser: trust.ASLocalRecurser{IA: cfg.IA},
		Router: trust.AuthRouter{
			ISD:    cfg.IA.I,
			DB:     cfg.TrustDB,
			Router: trustRouter,
		},
	}
	trustRouter.Pather.Fetcher = segfetcher.FetcherConfig{
		QueryInterval: cfg.QueryInterval,
		LocalIA:       cfg.IA,
		Verifier:      compat.Verifier{Verifier: trust.Verifier{Engine: provider}},
		PathDB:        cfg.PathDB,
		RevCache:      cfg.RevCache,
		RequestAPI:    cfg.RPC,
		DstProvider:   cfg.DstProvider,
		Splitter: &segfetcher.MultiSegmentSplitter{
			Local:     cfg.IA,
			Inspector: cfg.Inspector,
		},
		MetricsNamespace: metrics.PSNamespace,
		LocalInfo:        segreq.CreateLocalInfo(cfg.Core, cfg.IA, cfg.Inspector),
	}.New()
	return provider
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

// LoadClientChains loads the client certificate chains.
func LoadClientChains(db renewal.DB, configDir string) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	return cstrust.ClientLoader{
		Dir:      filepath.Join(configDir, "crypto/ca/clients"),
		ClientDB: db,
	}.LoadClientChains(ctx)
}

// NewChainBuilder creates a renewing chain builder.
func NewChainBuilder(ia addr.IA, db trust.DB, maxVal time.Duration,
	configDir string) cstrust.ChainBuilder {

	return cstrust.ChainBuilder{
		PolicyGen: &cstrust.CachingPolicyGen{
			PolicyGen: cstrust.LoadingPolicyGen{
				Validity: maxVal,
				CertProvider: cstrust.CACertLoader{
					IA:  ia,
					DB:  db,
					Dir: filepath.Join(configDir, "crypto/ca"),
				},
				KeyRing: cstrust.LoadingRing{
					Dir: filepath.Join(configDir, "crypto/ca"),
				},
			},
		},
	}
}
