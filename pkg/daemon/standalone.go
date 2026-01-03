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
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/cp"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/daemon/private/engine"
	"github.com/scionproto/scion/pkg/daemon/private/standalone"
	"github.com/scionproto/scion/pkg/daemon/private/trust"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	pkgmetrics "github.com/scionproto/scion/pkg/metrics"
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
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

// DefaultTopologyFile is the default path to the topology file.
const DefaultTopologyFile = "/etc/scion/topology.json"

// DefaultCertsDir is the default directory for trust material.
const DefaultCertsDir = "/etc/scion/certs"

// standaloneOption is a functional option for NewStandaloneConnector.
type standaloneOption func(*standaloneOptions)

type standaloneOptions struct {
	certsDir               string
	disableSegVerification bool
	enablePeriodicCleanup  bool
	enableMetrics          bool
}

// WithCertsDir sets the configuration directory for trust material.
// Defaults to /etc/scion/certs.
func WithCertsDir(dir string) standaloneOption {
	return func(o *standaloneOptions) {
		o.certsDir = dir
	}
}

// WithDisableSegVerification disables segment verification.
// WARNING: This should NOT be used in production!
func WithDisableSegVerification() standaloneOption {
	return func(o *standaloneOptions) {
		o.disableSegVerification = true
	}
}

// WithPeriodicCleanup enables periodic cleanup of path database and revocation cache.
func WithPeriodicCleanup() standaloneOption {
	return func(o *standaloneOptions) {
		o.enablePeriodicCleanup = true
	}
}

// WithMetrics enables metrics collection for the standalone daemon.
func WithMetrics() standaloneOption {
	return func(o *standaloneOptions) {
		o.enableMetrics = true
	}
}

// LoadCPInfoFromFile loads a topology from a file.
// The returned topology can be passed to NewStandaloneConnector.
//
// Most users should use NewStandaloneConnector() directly with a file path
// instead of using this function.
func LoadCPInfoFromFile(topoFile string) (cp.CPInfo, error) {
	return cp.LoadFromTopoFile(topoFile)
}

// NewStandaloneConnector creates a daemon Connector that runs locally without a daemon process.
// It requires a CPInfo (use LoadCPInfoFromFile to create one from a file) and accepts
// functional options for configuration.
//
// The returned Connector can be used directly by SCION applications instead of connecting
// to a daemon via gRPC.
//
// Example:
//
//	cpinfo, err := daemon.LoadCPInfoFromFile("/path/to/topology.json")
//	if err != nil { ... }
//	conn, err := daemon.NewStandaloneConnector(ctx, cpinfo,
//	    daemon.WithCertsDir("/path/to/certs"),
//	    daemon.WithMetrics(),
//	)
func NewStandaloneConnector(
	ctx context.Context, cpInfo cp.CPInfo, opts ...standaloneOption,
) (Connector, error) {

	options := &standaloneOptions{
		certsDir: DefaultCertsDir,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Create dialer for control service
	dialer := &grpc.TCPDialer{
		SvcResolver: func(dst addr.SVC) []resolver.Address {
			if base := dst.Base(); base != addr.SvcCS {
				panic("unsupported address type, possible implementation error: " +
					base.String())
			}
			targets := []resolver.Address{}
			for _, entry := range cpInfo.ControlServiceAddresses() {
				targets = append(targets, resolver.Address{Addr: entry.String()})
			}
			return targets
		},
	}

	// Create RPC requester for segment fetching
	var requester segfetcher.RPC = &segfetchergrpc.Requester{
		Dialer: dialer,
	}

	// Initialize in-memory path storage
	pathDB, err := storage.NewInMemoryPathStorage()
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
		cleaner = periodic.Start(pathdb.NewCleaner(pathDB, "sd_segments"),
			300*time.Second, 295*time.Second)

		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		rcCleaner = periodic.Start(revcache.NewCleaner(revCache, "sd_revocation"),
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
		verifier = segverifier.AcceptAll{}
	} else {
		trustDB, err = storage.NewInMemoryTrustStorage()
		if err != nil {
			return nil, serrors.Wrap("initializing trust database", err)
		}
		trustDB = truststoragemetrics.WrapDB(trustDB, truststoragemetrics.Config{
			Driver: string(storage.BackendSqlite),
			QueriesTotal: pkgmetrics.NewPromCounterFrom(
				prometheus.CounterOpts{
					Name: "trustengine_db_queries_total",
					Help: "Total queries to the database",
				},
				[]string{"driver", "operation", "result"},
			),
		})
		trustEngine, err := trust.Engine(
			ctx, options.certsDir, cpInfo.IA(), trustDB, dialer,
		)
		if err != nil {
			return nil, serrors.Wrap("creating trust engine", err)
		}
		trustEngine.Inspector = privtrust.CachingInspector{
			Inspector:          trustEngine.Inspector,
			Cache:              cache.New(time.Minute, time.Minute),
			CacheHits:          pkgmetrics.NewPromCounter(trustmetrics.CacheHitsTotal),
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
				CacheHits:          pkgmetrics.NewPromCounter(trustmetrics.CacheHitsTotal),
				MaxCacheExpiration: time.Minute,
			},
		}
		inspector = trustEngine.Inspector
	}

	// Create fetcher
	newFetcher := fetcher.NewFetcher(
		fetcher.FetcherConfig{
			IA:            cpInfo.IA(),
			MTU:           cpInfo.MTU(),
			Core:          cpInfo.Core(),
			NextHopper:    cpInfo,
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
		IA:          cpInfo.IA(),
		MTU:         cpInfo.MTU(),
		CPInfo:      cpInfo,
		Fetcher:     newFetcher,
		RevCache:    revCache,
		ASInspector: inspector,
		DRKeyClient: nil, // DRKey not supported in standalone daemon
	}

	var standaloneMetrics standalone.Metrics
	if options.enableMetrics {
		standaloneMetrics = standalone.NewStandaloneMetrics()
	}

	standaloneDaemon := &standalone.Daemon{
		Engine:        daemonEngine,
		Metrics:       standaloneMetrics,
		CPInfo:        cpInfo,
		PathDBCleaner: cleaner,
		PathDB:        pathDB,
		RevCache:      revCache,
		RcCleaner:     rcCleaner,
		TrustDB:       trustDB,
		TRCLoaderTask: trcLoaderTask,
	}

	return standaloneDaemon, nil
}
