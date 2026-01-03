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
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/segment/segfetcher"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	segverifier "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/storage"
	truststoragemetrics "github.com/scionproto/scion/private/storage/trust/metrics"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/compat"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

// StandaloneOption is a functional option for NewStandaloneConnector.
type StandaloneOption func(*standaloneOptions)

// DefaultTopologyFile is the default path to the topology file.
const DefaultTopologyFile = "/etc/scion/topology.json"

// DefaultCertsDir is the default directory for trust material.
const DefaultCertsDir = "/etc/scion/certs"

type standaloneOptions struct {
	certsDir               string
	disableSegVerification bool
	enablePeriodicCleanup  bool
	enableMetrics          bool
}

// WithCertsDir sets the configuration directory for trust material.
// Defaults to /etc/scion/certs.
func WithCertsDir(dir string) StandaloneOption {
	return func(o *standaloneOptions) {
		o.certsDir = dir
	}
}

// WithDisableSegVerification disables segment verification.
// WARNING: This should NOT be used in production!
func WithDisableSegVerification() StandaloneOption {
	return func(o *standaloneOptions) {
		o.disableSegVerification = true
	}
}

// WithPeriodicCleanup enables periodic cleanup of path database and revocation cache.
func WithPeriodicCleanup() StandaloneOption {
	return func(o *standaloneOptions) {
		o.enablePeriodicCleanup = true
	}
}

// WithMetrics enables metrics collection for the standalone daemon.
func WithMetrics() StandaloneOption {
	return func(o *standaloneOptions) {
		o.enableMetrics = true
	}
}

// LoadTopologyFromFile loads a topology from a file.
// The returned Topology can be passed to NewStandaloneConnector.
func LoadTopologyFromFile(topoFile string) (Topology, error) {
	loader, err := topology.NewLoader(
		topology.LoaderCfg{
			File:      topoFile,
			Reload:    nil,
			Validator: &topology.DefaultValidator{},
			Metrics:   newLoaderMetrics(),
		},
	)
	if err != nil {
		return nil, serrors.Wrap("creating topology loader", err)
	}
	return loader, nil
}

// newLoaderMetrics creates metrics for the topology loader.
func newLoaderMetrics() topology.LoaderMetrics {
	updates := prom.NewCounterVec(
		"", "",
		"topology_updates_total",
		"The total number of updates.",
		[]string{prom.LabelResult},
	)
	return topology.LoaderMetrics{
		ValidationErrors: metrics.NewPromCounter(updates).With(prom.LabelResult, "err_validate"),
		ReadErrors:       metrics.NewPromCounter(updates).With(prom.LabelResult, "err_read"),
		LastUpdate: metrics.NewPromGauge(
			prom.NewGaugeVec(
				"", "",
				"topology_last_update_time",
				"Timestamp of the last successful update.",
				[]string{},
			),
		),
		Updates: metrics.NewPromCounter(updates).With(prom.LabelResult, prom.Success),
	}
}

// StandaloneDaemon implements the daemon.Connector interface by directly
// delegating to a DaemonEngine. This allows in-process usage of daemon
// functionality without going through gRPC.
// Also collects metrics for all operations.
//
// Close() will clean up all resources, including the topology if it implements
// io.Closer.
type StandaloneDaemon struct {
	Engine  *DaemonEngine
	Metrics StandaloneMetrics

	topo          Topology
	pathDBCleaner *periodic.Runner
	pathDB        storage.PathDB
	revCache      revcache.RevCache
	rcCleaner     *periodic.Runner
	trustDB       storage.TrustDB
	trcLoaderTask *periodic.Runner
}

// NewStandaloneConnector creates a daemon Connector that runs locally without a daemon process.
// It requires a Topology (use LoadTopologyFromFile to create one from a file) and accepts
// functional options for configuration.
//
// The returned Connector can be used directly by SCION applications instead of connecting
// to a daemon via gRPC.
//
// Example:
//
//	topo, err := daemon.LoadTopologyFromFile("/path/to/topology.json")
//	if err != nil { ... }
//	conn, err := daemon.NewStandaloneConnector(ctx, topo,
//	    daemon.WithCertsDir("/path/to/certs"),
//	    daemon.WithMetrics(),
//	)
func NewStandaloneConnector(
	ctx context.Context, topo Topology, opts ...StandaloneOption,
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
	if options.enablePeriodicCleanup {
		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		cleaner = periodic.Start(pathdb.NewCleaner(pathDB, "sd_segments"),
			300*time.Second, 295*time.Second)

		//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
		rcCleaner = periodic.Start(revcache.NewCleaner(revCache, "sd_revocation"),
			10*time.Second, 10*time.Second)
	}

	var trustDB storage.TrustDB
	var inspector trust.Inspector
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
			QueriesTotal: metrics.NewPromCounterFrom(
				prometheus.CounterOpts{
					Name: "trustengine_db_queries_total",
					Help: "Total queries to the database",
				},
				[]string{"driver", "operation", prom.LabelResult},
			),
		})
		engine, err := TrustEngine(
			ctx, options.certsDir, topo.IA(), trustDB, dialer,
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
			Verifier: trust.Verifier{
				Engine:             engine,
				Cache:              cache.New(time.Minute, time.Minute),
				CacheHits:          metrics.NewPromCounter(trustmetrics.CacheHitsTotal),
				MaxCacheExpiration: time.Minute,
			},
		}
		inspector = engine.Inspector
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
	daemonEngine := &DaemonEngine{
		IA:          topo.IA(),
		MTU:         topo.MTU(),
		Topology:    topo,
		Fetcher:     newFetcher,
		RevCache:    revCache,
		ASInspector: inspector,
		DRKeyClient: nil, // DRKey not supported in standalone daemon
	}

	var standaloneMetrics StandaloneMetrics
	if options.enableMetrics {
		standaloneMetrics = NewStandaloneMetrics()
	}

	standalone := &StandaloneDaemon{
		Engine:        daemonEngine,
		Metrics:       standaloneMetrics,
		topo:          topo,
		pathDBCleaner: cleaner,
		pathDB:        pathDB,
		revCache:      revCache,
		rcCleaner:     rcCleaner,
		trustDB:       trustDB,
		trcLoaderTask: trcLoaderTask,
	}

	return standalone, nil
}

// LocalIA returns the local ISD-AS number.
func (s *StandaloneDaemon) LocalIA(ctx context.Context) (addr.IA, error) {
	start := time.Now()
	ia, err := s.Engine.LocalIA(ctx)
	s.Metrics.LocalIA.observe(err, time.Since(start))
	return ia, err
}

// PortRange returns the beginning and the end of the SCION/UDP endhost port range.
func (s *StandaloneDaemon) PortRange(ctx context.Context) (uint16, uint16, error) {
	start := time.Now()
	startPort, endPort, err := s.Engine.PortRange(ctx)
	s.Metrics.PortRange.observe(err, time.Since(start))
	return startPort, endPort, err
}

// Interfaces returns the map of interface identifiers to the underlay internal address.
func (s *StandaloneDaemon) Interfaces(ctx context.Context) (map[uint16]netip.AddrPort, error) {
	start := time.Now()
	result, err := s.Engine.Interfaces(ctx)
	s.Metrics.Interfaces.observe(err, time.Since(start))
	return result, err
}

// Paths requests from the daemon a set of end to end paths between the source and destination.
func (s *StandaloneDaemon) Paths(
	ctx context.Context,
	dst, src addr.IA,
	f PathReqFlags,
) ([]snet.Path, error) {
	start := time.Now()
	paths, err := s.Engine.Paths(ctx, dst, src, f)
	s.Metrics.Paths.observe(err, time.Since(start), prom.LabelDst, dst.ISD().String())
	return paths, err
}

// ASInfo requests information about an AS. The zero IA returns local AS info.
func (s *StandaloneDaemon) ASInfo(ctx context.Context, ia addr.IA) (ASInfo, error) {
	start := time.Now()
	asInfo, err := s.Engine.ASInfo(ctx, ia)
	s.Metrics.ASInfo.observe(err, time.Since(start))
	return asInfo, err
}

// SVCInfo requests information about addresses and ports of infrastructure services.
func (s *StandaloneDaemon) SVCInfo(
	ctx context.Context,
	_ []addr.SVC,
) (map[addr.SVC][]string, error) {
	start := time.Now()
	uris, err := s.Engine.SVCInfo(ctx)
	s.Metrics.SVCInfo.observe(err, time.Since(start))
	if err != nil {
		return nil, err
	}
	result := make(map[addr.SVC][]string)
	if len(uris) > 0 {
		result[addr.SvcCS] = uris
	}
	return result, nil
}

// RevNotification sends a RevocationInfo message to the daemon.
func (s *StandaloneDaemon) RevNotification(
	ctx context.Context,
	revInfo *path_mgmt.RevInfo,
) error {
	start := time.Now()
	err := s.Engine.NotifyInterfaceDown(ctx, revInfo.RawIsdas, uint64(revInfo.IfID))
	s.Metrics.InterfaceDown.observe(err, time.Since(start))
	return err
}

// DRKeyGetASHostKey requests an AS-Host Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetASHostKey(ctx, meta)
	s.Metrics.DRKeyASHost.observe(err, time.Since(start))
	return key, err
}

// DRKeyGetHostASKey requests a Host-AS Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetHostASKey(
	ctx context.Context,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetHostASKey(ctx, meta)
	s.Metrics.DRKeyHostAS.observe(err, time.Since(start))
	return key, err
}

// DRKeyGetHostHostKey requests a Host-Host Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetHostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {
	start := time.Now()
	key, err := s.Engine.DRKeyGetHostHostKey(ctx, meta)
	s.Metrics.DRKeyHostHost.observe(err, time.Since(start))
	return key, err
}

func (s *StandaloneDaemon) Close() error {
	var err error
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
	// Close topology if it implements io.Closer.
	if closer, ok := s.topo.(io.Closer); ok {
		err1 := closer.Close()
		err = errors.Join(err, err1)
	}
	return err
}

// Compile-time assertion that StandaloneDaemon implements daemon.Connector.
var _ Connector = (*StandaloneDaemon)(nil)

// StandaloneMetrics contains metrics for all StandaloneDaemon operations.
type StandaloneMetrics struct {
	LocalIA       requestMetric
	PortRange     requestMetric
	Interfaces    requestMetric
	Paths         requestMetric
	ASInfo        requestMetric
	SVCInfo       requestMetric
	InterfaceDown requestMetric
	DRKeyASHost   requestMetric
	DRKeyHostAS   requestMetric
	DRKeyHostHost requestMetric
}

// requestMetric contains the metrics for a given request type.
type requestMetric struct {
	Requests metrics.Counter
	Latency  metrics.Histogram
}

func (m requestMetric) observe(err error, latency time.Duration, extraLabels ...string) {
	result := standaloneResultFromErr(err)
	if m.Requests != nil {
		m.Requests.With(append([]string{prom.LabelResult, result}, extraLabels...)...).Add(1)
	}
	if m.Latency != nil {
		m.Latency.With(prom.LabelResult, result).Observe(latency.Seconds())
	}
}

func standaloneResultFromErr(err error) string {
	if err == nil {
		return prom.Success
	}
	if serrors.IsTimeout(err) {
		return prom.ErrTimeout
	}
	return prom.ErrNotClassified
}

// NewStandaloneMetrics creates metrics for StandaloneDaemon operations.
func NewStandaloneMetrics() StandaloneMetrics {
	resultLabels := []string{prom.LabelResult}
	pathLabels := []string{prom.LabelResult, prom.LabelDst}
	return StandaloneMetrics{
		LocalIA:    newRequestMetric("local_ia", "local IA", resultLabels),
		PortRange:  newRequestMetric("port_range", "port range", resultLabels),
		Interfaces: newRequestMetric("interfaces", "interfaces", resultLabels),
		Paths:      newRequestMetric("paths", "path", pathLabels),
		ASInfo:     newRequestMetric("as_info", "AS info", resultLabels),
		SVCInfo:    newRequestMetric("svc_info", "SVC info", resultLabels),
		InterfaceDown: newRequestMetric(
			"interface_down", "interface down notification", resultLabels,
		),
		DRKeyASHost:   newRequestMetric("drkey_as_host", "DRKey AS-Host", resultLabels),
		DRKeyHostAS:   newRequestMetric("drkey_host_as", "DRKey Host-AS", resultLabels),
		DRKeyHostHost: newRequestMetric("drkey_host_host", "DRKey Host-Host", resultLabels),
	}
}

func newRequestMetric(subsystem, description string, labels []string) requestMetric {
	return requestMetric{
		Requests: metrics.NewPromCounterFrom(
			prometheus.CounterOpts{
				Namespace: "standalone_daemon",
				Subsystem: subsystem,
				Name:      "requests_total",
				Help:      "The amount of " + description + " requests.",
			},
			labels,
		),
		Latency: metrics.NewPromHistogramFrom(
			prometheus.HistogramOpts{
				Namespace: "standalone_daemon",
				Subsystem: subsystem,
				Name:      "request_duration_seconds",
				Help:      "Time to handle " + description + " requests.",
				Buckets:   prom.DefaultLatencyBuckets,
			},
			[]string{prom.LabelResult},
		),
	}
}
