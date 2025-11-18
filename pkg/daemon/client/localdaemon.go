// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"context"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/server"
	"github.com/scionproto/scion/pkg/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/grpc"
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
	"github.com/scionproto/scion/private/topology"
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

// NewLocalDaemon creates a daemon Connector that runs locally without a daemon process.
// It loads the topology from the specified file and initializes all necessary components
// for path lookups and AS information queries.
//
// The returned Connector can be used directly by SCION applications instead of connecting
// to a daemon via gRPC.
//
// Note: This function starts background tasks (cleaner, TRC loader) that should be stopped
// when done. The caller should handle cleanup appropriately, typically via context cancellation.
func NewLocalDaemon(ctx context.Context, topoFile string) (daemon.Connector, error) {
	if topoFile == "" {
		return nil, serrors.New("topology file path is required")
	}

	// Load topology
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      topoFile,
		Reload:    nil, // No reload for local daemon
		Validator: &topology.DefaultValidator{},
		Metrics:   loaderMetrics(),
	})
	if err != nil {
		return nil, serrors.Wrap("creating topology loader", err)
	}
	g, errCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		return topo.Run(errCtx)
	})

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

	// Start path DB cleaner
	cleaner := periodic.Start(pathdb.NewCleaner(pathDB, "sd_segments"),
		300*time.Second, 295*time.Second)
	go func() { // Cleanup on context done
		defer log.HandlePanic()
		<-ctx.Done()
		cleaner.Stop()
		pathDB.Close()
	}()

	// Initialize revocation cache
	revCache := storage.NewRevocationStorage()
	go func() { // Cleanup on context done
		defer log.HandlePanic()
		<-ctx.Done()
		revCache.Close()
	}()

	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	rcCleaner := periodic.Start(revcache.NewCleaner(revCache, "sd_revocation"),
		10*time.Second, 10*time.Second)
	go func() { // Cleanup on context done
		defer log.HandlePanic()
		<-ctx.Done()
		rcCleaner.Stop()
	}()

	// Create fetcher
	newFetcher := fetcher.NewFetcher(
		fetcher.FetcherConfig{
			IA:            topo.IA(),
			MTU:           topo.MTU(),
			Core:          topo.Core(),
			NextHopper:    topo,
			RPC:           requester,
			PathDB:        pathDB,
			Inspector:     nil,
			Verifier:      acceptAllVerifier{},
			RevCache:      revCache,
			QueryInterval: 0,
		},
	)

	// Create server metrics
	serverMetrics := newServerMetrics()

	// Create and return the connector
	connector := &server.ConnectorBackend{
		IA:          topo.IA(),
		MTU:         topo.MTU(),
		Topology:    topo,
		Fetcher:     newFetcher,
		RevCache:    revCache,
		DRKeyClient: nil,
		Metrics:     serverMetrics,
	}

	return connector, nil
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
