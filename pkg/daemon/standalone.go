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

package daemon

import (
	"context"
	"time"

	"github.com/patrickmn/go-cache"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/asinfo"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/daemon/private/engine"
	"github.com/scionproto/scion/pkg/daemon/private/standalone"
	"github.com/scionproto/scion/pkg/daemon/private/trust"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/segment/segfetcher"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	segverifier "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/storage"
	truststoragemetrics "github.com/scionproto/scion/private/storage/trust/metrics"
	privtrust "github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/compat"
)

// StandaloneConnectorOption is a functional option for NewStandaloneConnector.
type StandaloneConnectorOption func(*standaloneConnectorOptions)

type standaloneConnectorOptions struct {
	certsDir               string
	disableSegVerification bool
	enablePeriodicCleanup  bool
	metrics                StandaloneMetrics
}

// WithCertsDir sets the directory containing TRC certificates for trust material.
// This option is required unless segment verification is disabled.
func WithCertsDir(dir string) StandaloneConnectorOption {
	return func(o *standaloneConnectorOptions) {
		o.certsDir = dir
	}
}

// WithDisabledSegVerification disables segment verification.
// WARNING: This should NOT be used in production!
func WithDisabledSegVerification() StandaloneConnectorOption {
	return func(o *standaloneConnectorOptions) {
		o.disableSegVerification = true
	}
}

// WithPeriodicCleanup enables periodic cleanup of path database and revocation cache.
func WithPeriodicCleanup() StandaloneConnectorOption {
	return func(o *standaloneConnectorOptions) {
		o.enablePeriodicCleanup = true
	}
}

func WithStandaloneMetrics(metrics StandaloneMetrics) StandaloneConnectorOption {
	return func(o *standaloneConnectorOptions) {
		o.metrics = metrics
	}
}

// LoadASInfoFromFile loads local AS Information from a file.
// The returned struct can be passed to NewStandaloneConnector.
func LoadASInfoFromFile(topoFile string) (asinfo.LocalASInfo, error) {
	return asinfo.LoadFromTopoFile(topoFile)
}

// NewStandaloneConnector creates a daemon Connector that runs locally without a daemon process.
// It requires a LocalASInfo (use LoadASInfoFromFile to create one from a file) and accepts
// functional options for configuration.
//
// The returned Connector can be used directly by SCION applications instead of connecting
// to a daemon via gRPC.
//
// Example:
//
//	localASInfo, err := daemon.LoadASInfoFromFile("/path/to/topology.json")
//	if err != nil { ... }
//	conn, err := daemon.NewStandaloneConnector(ctx, localASInfo,
//	    daemon.WithCertsDir("/path/to/certs"),
//	    daemon.WithStandaloneMetrics(...),
//	)
func NewStandaloneConnector(
	ctx context.Context, localASInfo asinfo.LocalASInfo, opts ...StandaloneConnectorOption,
) (Connector, error) {

	options := &standaloneConnectorOptions{}
	for _, opt := range opts {
		opt(options)
	}
	metrics := options.metrics

	// Validate that certsDir is set unless segment verification is disabled
	if options.certsDir == "" && !options.disableSegVerification {
		return nil, serrors.New("WithCertsDir is required unless segment verification is disabled")
	}

	// Create dialer for control service
	dialer := &grpc.TCPDialer{
		SvcResolver: func(dst addr.SVC) []resolver.Address {
			if base := dst.Base(); base != addr.SvcCS {
				panic("unsupported address type, possible implementation error: " +
					base.String())
			}
			var targets []resolver.Address
			for _, entry := range localASInfo.ControlServiceAddresses() {
				targets = append(targets, resolver.Address{Addr: entry.String()})
			}
			return targets
		},
	}

	// Create RPC requester for segment fetching
	var requester segfetcher.RPC = &segfetchergrpc.Requester{
		Dialer: dialer,
	}

	cleanerMetrics := NewCleanerMetrics()
	// Initialize in-memory path storage
	pathDB, err := storage.NewInMemoryPathStorage(cleanerMetrics.PathStorage)
	if err != nil {
		return nil, serrors.Wrap("initializing path storage", err)
	}

	// Initialize revocation cache
	revCache := storage.NewRevocationStorage()

	// Start periodic cleaners if enabled
	var cleaner *periodic.Runner
	var rcCleaner *periodic.Runner
	if options.enablePeriodicCleanup {
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		cleaner = periodic.Start(pathdb.NewCleaner(pathDB, "sd_segments",
			cleanerMetrics.SDSegments),
			300*time.Second, 295*time.Second)

		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		rcCleaner = periodic.Start(revcache.NewCleaner(revCache, "sd_revocation",
			cleanerMetrics.SDRevocation),
			10*time.Second, 10*time.Second)
	}

	var trustDB storage.TrustDB
	var inspector privtrust.Inspector
	var verifier segverifier.Verifier
	var trcLoaderTask *periodic.Runner

	// Create trust engine unless verification is disabled
	if options.disableSegVerification {
		log.Info("SEGMENT VERIFICATION DISABLED -- SHOULD NOT USE IN PRODUCTION!")
		inspector = nil // avoids requiring trust material
		verifier = segverifier.AcceptAllVerifier{}
	} else {
		trustDB, err = storage.NewInMemoryTrustStorage()
		if err != nil {
			return nil, serrors.Wrap("initializing trust database", err)
		}
		trustDB = truststoragemetrics.WrapDB(trustDB, truststoragemetrics.Config{
			Driver:       string(storage.BackendSqlite),
			QueriesTotal: metrics.TrustStorageQueries,
		})
		trustEngine, err := trust.NewEngine(
			ctx, options.certsDir, localASInfo.IA(), trustDB, dialer, metrics.Trust,
		)
		if err != nil {
			return nil, serrors.Wrap("creating trust engine", err)
		}
		trustEngine.Inspector = privtrust.CachingInspector{
			Inspector:          trustEngine.Inspector,
			Cache:              cache.New(time.Minute, time.Minute),
			CacheHits:          metrics.Trust.CacheHits,
			MaxCacheExpiration: time.Minute,
		}
		trcLoader := privtrust.TRCLoader{
			Dir: options.certsDir,
			DB:  trustDB,
		}
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		trcLoaderTask = periodic.Start(
			periodic.Func{
				Task: func(ctx context.Context) {
					res, err := trcLoader.Load(ctx)
					if err != nil {
						log.SafeInfo(log.FromCtx(ctx), "TRC loading failed", "err", err)
					}
					if len(res.Loaded) > 0 {
						log.SafeInfo(
							log.FromCtx(ctx),
							"Loaded TRCs from disk", "trcs", res.Loaded,
						)
					}
				},
				TaskName: "daemon_trc_loader",
			}, 10*time.Second, 10*time.Second,
		)

		verifier = compat.Verifier{
			Verifier: privtrust.Verifier{
				Engine:             trustEngine,
				Cache:              cache.New(time.Minute, time.Minute),
				CacheHits:          metrics.Trust.CacheHits,
				MaxCacheExpiration: time.Minute,
				Verifications:      metrics.Trust.VerifierSignatures,
			},
		}
		inspector = trustEngine.Inspector
	}

	// Create fetcher
	newFetcher := fetcher.NewFetcher(
		fetcher.FetcherConfig{
			IA:            localASInfo.IA(),
			MTU:           localASInfo.MTU(),
			Core:          localASInfo.Core(),
			NextHopper:    localASInfo,
			RPC:           requester,
			PathDB:        pathDB,
			Inspector:     inspector,
			Verifier:      verifier,
			RevCache:      revCache,
			QueryInterval: 0,
		},
	)

	// Create the daemon engine
	daemonEngine := &engine.DaemonEngine{
		IA:          localASInfo.IA(),
		MTU:         localASInfo.MTU(),
		LocalASInfo: localASInfo,
		Fetcher:     newFetcher,
		RevCache:    revCache,
		ASInspector: inspector,
		// TODO(emairoll): Implement DRKey for standalone mode
		DRKeyClient: nil,
	}

	standaloneDaemon := &standalone.Daemon{
		Engine:        daemonEngine,
		Metrics:       metrics.Standalone,
		LocalASInfo:   localASInfo,
		PathDBCleaner: cleaner,
		PathDB:        pathDB,
		RevCache:      revCache,
		RcCleaner:     rcCleaner,
		TrustDB:       trustDB,
		TRCLoaderTask: trcLoaderTask,
	}

	return standaloneDaemon, nil
}
