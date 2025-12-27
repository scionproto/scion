// Copyright 2025 ETH Zurich
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
	"errors"
	"net"
	"path/filepath"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/pkg/addr"
	daemonpkg "github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/daemon/server"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/segment/segfetcher"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	infra "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/storage"
	truststoragemetrics "github.com/scionproto/scion/private/storage/trust/metrics"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/compat"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

// acceptAllVerifier accepts all path segments without verification.
type acceptAllVerifier struct{}

func (acceptAllVerifier) Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte,
) (*signed.Message, error) {
	return nil, nil
}

func (v acceptAllVerifier) WithServer(net.Addr) infra.Verifier {
	return v
}

func (v acceptAllVerifier) WithIA(addr.IA) infra.Verifier {
	return v
}

func (v acceptAllVerifier) WithValidity(cppki.Validity) infra.Verifier {
	return v
}

type StandaloneOptions struct {
	// either TopoFile or Topo must be set
	TopoFile string
	// either TopoFile or Topo must be set
	Topo *topology.Loader

	// global configuration directory, used for trust engine setup
	ConfigDir string

	DisableSegVerification bool
	EnablePeriodicCleanup  bool
	EnableMetrics          bool
}

// wrapper for the standalone service to keep track of background tasks and storages to be closed
type wrapperWithClose struct {
	daemonpkg.Connector

	// background tasks and storages to be closed on Close()
	pathDBCleaner *periodic.Runner
	pathDB        storage.PathDB
	revCache      revcache.RevCache
	rcCleaner     *periodic.Runner
	trustDB       storage.TrustDB
	trcLoaderTask *periodic.Runner
}

// NewStandaloneService creates a daemon Connector that runs locally without a daemon process.
// It accepts a topology either as loader or as file path, and initializes all necessary
// components for path lookups and AS information queries.
//
// The returned Connector can be used directly by SCION applications instead of connecting
// to a daemon via gRPC.
//
// Note: This function starts background tasks (cleaner, TRC loader) that should be stopped
// when done. The caller should handle cleanup appropriately, typically via context cancellation.
func NewStandaloneService(ctx context.Context, options StandaloneOptions,
) (daemonpkg.Connector, error) {
	if options.Topo == nil && options.TopoFile == "" {
		return nil, serrors.New("either topology or topology file path must be provided")
	}
	if options.ConfigDir == "" {
		if options.TopoFile != "" {
			options.ConfigDir = filepath.Dir(options.TopoFile)
		} else {
			return nil, serrors.New("configuration directory must be provided")
		}
	}

	g, errCtx := errgroup.WithContext(ctx)
	topo := options.Topo
	if topo == nil {
		// Load topology
		var err error
		topo, err = topology.NewLoader(topology.LoaderCfg{
			File:      options.TopoFile,
			Reload:    nil, // No reload for local daemon
			Validator: &topology.DefaultValidator{},
			Metrics:   loaderMetrics(),
		})

		if err != nil {
			return nil, serrors.Wrap("creating topology loader", err)
		}
		g.Go(func() error {
			defer log.HandlePanic()
			return topo.Run(errCtx)
		})
	}

	// Create dialer for control service
	dialer := &grpc.TCPDialer{
		SvcResolver: func(dst addr.SVC) []resolver.Address {
			if base := dst.Base(); base != addr.SvcCS {
				panic("unsupported address type, possible implementation error: " +
					base.String())
			}
			targets := []resolver.Address{}
			for _, entry := range topo.ControlServiceAddresses() {
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
	if options.EnablePeriodicCleanup {
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		cleaner = periodic.Start(pathdb.NewCleaner(pathDB, "sd_segments"),
			300*time.Second, 295*time.Second)

		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		rcCleaner = periodic.Start(revcache.NewCleaner(revCache, "sd_revocation"),
			10*time.Second, 10*time.Second)
	}

	var trustDB storage.TrustDB
	var inspector trust.Inspector
	var verifier infra.Verifier
	var trcLoaderTask *periodic.Runner

	if options.DisableSegVerification {
		// do not create trust engine to avoid requiring trust material
		inspector = nil
		verifier = acceptAllVerifier{}
	} else {
		// Create trust engine unless verification is disabled
		trustDB, err = storage.NewInMemoryTrustStorage()
		if err != nil {
			return nil, serrors.Wrap("initializing trust database", err)
		}
		trustDB = truststoragemetrics.WrapDB(trustDB, truststoragemetrics.Config{
			Driver: string(storage.BackendSqlite),
			QueriesTotal: metrics.NewPromCounterFrom(
				prometheus.CounterOpts{
					Name: "trustengine_db_queries_total",
					Help: "Total queries to the database",
				},
				[]string{"driver", "operation", prom.LabelResult},
			),
		})
		engine, err := daemonpkg.TrustEngine(
			errCtx, options.ConfigDir, topo.IA(), trustDB, dialer,
		)
		if err != nil {
			return nil, serrors.Wrap("creating trust engine", err)
		}
		engine.Inspector = trust.CachingInspector{
			Inspector:          engine.Inspector,
			Cache:              cache.New(time.Minute, time.Minute),
			CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
			MaxCacheExpiration: time.Minute,
		}
		trcLoader := trust.TRCLoader{
			Dir: filepath.Join(options.ConfigDir, "certs"),
			DB:  trustDB,
		}
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		trcLoaderTask = periodic.Start(periodic.Func{
			Task: func(ctx context.Context) {
				res, err := trcLoader.Load(ctx)
				if err != nil {
					log.SafeInfo(log.FromCtx(ctx), "TRC loading failed", "err", err)
				}
				if len(res.Loaded) > 0 {
					log.SafeInfo(log.FromCtx(ctx),
						"Loaded TRCs from disk", "trcs", res.Loaded)
				}
			},
			TaskName: "daemon_trc_loader",
		}, 10*time.Second, 10*time.Second)

		verifier = compat.Verifier{Verifier: trust.Verifier{
			Engine:             engine,
			Cache:              cache.New(time.Minute, time.Minute),
			CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
			MaxCacheExpiration: time.Minute,
		}}
	}

	// Create fetcher
	newFetcher := fetcher.NewFetcher(
		fetcher.FetcherConfig{
			IA:            topo.IA(),
			MTU:           topo.MTU(),
			Core:          topo.Core(),
			NextHopper:    topo,
			RPC:           requester,
			PathDB:        pathDB,
			Inspector:     inspector,
			Verifier:      verifier,
			RevCache:      revCache,
			QueryInterval: 0,
		},
	)

	// Create and return the connector
	var connector daemonpkg.Connector = &server.ConnectorBackend{
		IA:          topo.IA(),
		MTU:         topo.MTU(),
		Topology:    topo,
		Fetcher:     newFetcher,
		RevCache:    revCache,
		DRKeyClient: nil, // DRKey not supported in standalone daemon
	}

	if options.EnableMetrics {
		// Create server metrics
		serverMetrics := newServerMetrics()
		// Wrap connector with metrics
		connector = &server.ConnectorMetricsWrapper{
			Connector: connector,
			Metrics:   &serverMetrics,
		}
	}

	connectorWithClose := wrapperWithClose{
		Connector:     connector,
		pathDBCleaner: cleaner,
		pathDB:        pathDB,
		revCache:      revCache,
		rcCleaner:     rcCleaner,
		trustDB:       trustDB,
		trcLoaderTask: trcLoaderTask,
	}

	return connectorWithClose, nil
}

func (s wrapperWithClose) Close() error {
	err := s.Connector.Close()

	if s.pathDBCleaner != nil {
		s.pathDBCleaner.Stop()
	}
	if s.pathDB != nil {
		err1 := s.pathDB.Close()
		err = errors.Join(err, err1)
	}
	if s.revCache != nil {
		err1 := s.revCache.Close()
		err = errors.Join(err, err1)
	}
	if s.rcCleaner != nil {
		s.rcCleaner.Stop()
	}
	if s.trustDB != nil {
		err1 := s.trustDB.Close()
		err = errors.Join(err, err1)
	}
	if s.trcLoaderTask != nil {
		s.trcLoaderTask.Stop()
	}
	return err
}

// loaderMetrics creates metrics for the topology loader.
func loaderMetrics() topology.LoaderMetrics {
	updates := prom.NewCounterVec("", "",
		"topology_updates_total",
		"The total number of updates.",
		[]string{prom.LabelResult},
	)
	return topology.LoaderMetrics{
		ValidationErrors: metrics.NewPromCounter(updates).With(prom.LabelResult, "err_validate"),
		ReadErrors:       metrics.NewPromCounter(updates).With(prom.LabelResult, "err_read"),
		LastUpdate: metrics.NewPromGauge(
			prom.NewGaugeVec("", "",
				"topology_last_update_time",
				"Timestamp of the last successful update.",
				[]string{},
			),
		),
		Updates: metrics.NewPromCounter(updates).With(prom.LabelResult, prom.Success),
	}
}

// newServerMetrics creates metrics for the daemon
func newServerMetrics() server.Metrics {
	return server.Metrics{
		PathsRequests: server.RequestMetrics{
			Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
				Namespace: "local_sd",
				Subsystem: "path",
				Name:      "requests_total",
				Help:      "The amount of path requests received.",
			}, server.PathsRequestsLabels),
			Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
				Namespace: "local_sd",
				Subsystem: "path",
				Name:      "request_duration_seconds",
				Help:      "Time to handle path requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, server.LatencyLabels),
		},
		ASRequests: server.RequestMetrics{
			Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
				Namespace: "local_sd",
				Subsystem: "as_info",
				Name:      "requests_total",
				Help:      "The amount of AS requests received.",
			}, server.ASRequestsLabels),
			Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
				Namespace: "local_sd",
				Subsystem: "as_info",
				Name:      "request_duration_seconds",
				Help:      "Time to handle AS requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, server.LatencyLabels),
		},
		InterfacesRequests: server.RequestMetrics{
			Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
				Namespace: "local_sd",
				Subsystem: "if_info",
				Name:      "requests_total",
				Help:      "The amount of interfaces requests received.",
			}, server.InterfacesRequestsLabels),
			Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
				Namespace: "local_sd",
				Subsystem: "if_info",
				Name:      "request_duration_seconds",
				Help:      "Time to handle interfaces requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, server.LatencyLabels),
		},
		ServicesRequests: server.RequestMetrics{
			Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
				Namespace: "local_sd",
				Subsystem: "service_info",
				Name:      "requests_total",
				Help:      "The amount of services requests received.",
			}, server.ServicesRequestsLabels),
			Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
				Namespace: "local_sd",
				Subsystem: "service_info",
				Name:      "request_duration_seconds",
				Help:      "Time to handle services requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, server.LatencyLabels),
		},
		InterfaceDownNotifications: server.RequestMetrics{
			Requests: metrics.NewPromCounter(prom.SafeRegister(
				prometheus.NewCounterVec(prometheus.CounterOpts{
					Namespace: "local_sd",
					Name:      "received_revocations_total",
					Help:      "The amount of revocations received.",
				}, server.InterfaceDownNotificationsLabels)).(*prometheus.CounterVec),
			),
			Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
				Namespace: "local_sd",
				Subsystem: "revocation",
				Name:      "notification_duration_seconds",
				Help:      "Time to handle interface down notifications.",
				Buckets:   prom.DefaultLatencyBuckets,
			}, server.LatencyLabels),
		},
	}
}
