// Copyright 2018 ETH Zurich, Anapaya Systems
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

package sciond

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/sciond/fetcher"
	"github.com/scionproto/scion/go/pkg/sciond/internal/servers"
	"github.com/scionproto/scion/go/pkg/trust"
	trustgrpc "github.com/scionproto/scion/go/pkg/trust/grpc"
	trustmetrics "github.com/scionproto/scion/go/pkg/trust/metrics"
)

// InitTracer initializes the global tracer.
func InitTracer(tracing env.Tracing, id string) (io.Closer, error) {
	tracer, trCloser, err := tracing.NewTracer(id)
	if err != nil {
		return nil, err
	}
	opentracing.SetGlobalTracer(tracer)
	return trCloser, nil
}

// TrustEngine builds the trust engine backed by the trust database.
func TrustEngine(cfgDir string, db trust.DB, dialer libgrpc.Dialer) (trust.Engine, error) {
	certsDir := filepath.Join(cfgDir, "certs")
	loaded, err := trust.LoadTRCs(context.Background(), certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.WrapStr("loading TRCs", err)
	}
	log.Info("TRCs loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		if errors.Is(r, trust.ErrAlreadyExists) {
			log.Debug("Ignoring existing TRC", "file", f)
			continue
		}
		log.Info("Ignoring non-TRC", "file", f, "reason", r)
	}
	loaded, err = trust.LoadChains(context.Background(), certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.WrapStr("loading certificate chains",
			err)
	}
	log.Info("Certificate chains loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		if errors.Is(r, trust.ErrAlreadyExists) {
			log.Debug("Ignoring existing certificate chain", "file", f)
			continue
		}
		if errors.Is(r, trust.ErrOutsideValidity) {
			log.Debug("Ignoring certificate chain outside validity", "file", f)
			continue
		}
		log.Info("Ignoring non-certificate chain", "file", f, "reason", r)
	}
	return trust.Engine{
		Inspector: trust.DBInspector{DB: db},
		Provider: trust.FetchingProvider{
			DB: db,
			Fetcher: trustgrpc.Fetcher{
				IA:       itopo.Get().IA(),
				Dialer:   dialer,
				Requests: metrics.NewPromCounter(trustmetrics.RPC.Fetches),
			},
			Recurser: trust.LocalOnlyRecurser{},
			Router:   trust.LocalRouter{IA: itopo.Get().IA()},
		},
		DB: db,
	}, nil
}

// ServerConfig is the configuration for the daemon API server.
type ServerConfig struct {
	Fetcher      fetcher.Fetcher
	PathDB       pathdb.PathDB
	RevCache     revcache.RevCache
	Engine       trust.Engine
	TopoProvider topology.Provider
}

// NewServer constructs a daemon API server.
func NewServer(cfg ServerConfig) *servers.DaemonServer {
	return &servers.DaemonServer{
		Fetcher:      cfg.Fetcher,
		ASInspector:  cfg.Engine.Inspector,
		RevCache:     cfg.RevCache,
		TopoProvider: cfg.TopoProvider,
		Metrics: servers.Metrics{
			PathsRequests: servers.RequestMetrics{
				Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
					Namespace: "sd",
					Subsystem: "path",
					Name:      "requests_total",
					Help:      "The amount of path requests received.",
				}, servers.PathsRequestsLabels),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "path",
					Name:      "request_duration_seconds",
					Help:      "Time to handle path requests.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, servers.LatencyLabels),
			},
			ASRequests: servers.RequestMetrics{
				Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
					Namespace: "sd",
					Subsystem: "as_info",
					Name:      "requests_total",
					Help:      "The amount of AS requests received.",
				}, servers.ASRequestsLabels),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "as_info",
					Name:      "request_duration_seconds",
					Help:      "Time to handle AS requests.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, servers.LatencyLabels),
			},
			InterfacesRequests: servers.RequestMetrics{
				Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
					Namespace: "sd",
					Subsystem: "if_info",
					Name:      "requests_total",
					Help:      "The amount of interfaces requests received.",
				}, servers.InterfacesRequestsLabels),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "if_info",
					Name:      "request_duration_seconds",
					Help:      "Time to handle interfaces requests.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, servers.LatencyLabels),
			},
			ServicesRequests: servers.RequestMetrics{
				Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
					Namespace: "sd",
					Subsystem: "service_info",
					Name:      "requests_total",
					Help:      "The amount of services requests received.",
				}, servers.ServicesRequestsLabels),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "service_info",
					Name:      "request_duration_seconds",
					Help:      "Time to handle services requests.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, servers.LatencyLabels),
			},
			InterfaceDownNotifications: servers.RequestMetrics{
				Requests: metrics.NewPromCounter(prom.SafeRegister(
					prometheus.NewCounterVec(prometheus.CounterOpts{
						Namespace: "sd",
						Name:      "received_revocations_total",
						Help:      "The amount of revocations received.",
					}, servers.InterfaceDownNotificationsLabels)).(*prometheus.CounterVec),
				),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "revocation",
					Name:      "notification_duration_seconds",
					Help:      "Time to handle interface down notifications.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, servers.LatencyLabels),
			},
		},
	}
}

// APIAddress returns the API address to listen on, based on the provided
// address. Addresses with missing or zero port are returned with the default
// daemon port. All other addresses are returned without modification. If the
// input is garbage, the output will also be garbage.
func APIAddress(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	switch {
	case err != nil:
		return net.JoinHostPort(listen, strconv.Itoa(sciond.DefaultAPIPort))
	case port == "0", port == "":
		return net.JoinHostPort(host, strconv.Itoa(sciond.DefaultAPIPort))
	default:
		return listen
	}
}
