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
	"io"
	"net"
	"path/filepath"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	sdpb "github.com/scionproto/scion/go/pkg/proto/daemon"
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
		log.Info("Ignoring non-TRC", "file", f, "reason", r)
	}
	loaded, err = trust.LoadChains(context.Background(), certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.WrapStr("loading certificate chains",
			err)
	}
	log.Info("Certificate chains loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
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

// ServerCfg is the configuration for the API server.
type ServerCfg struct {
	Fetcher  fetcher.Fetcher
	PathDB   pathdb.PathDB
	RevCache revcache.RevCache
	Engine   trust.Engine
}

// GRPCServer creates function that will serve the SCION daemon API via gRPC.
// Note that the function is blocking.
func GRPCServer(listen string, cfg ServerCfg) func() error {
	return func() error {
		listener, err := net.Listen("tcp", listen)
		if err != nil {
			return serrors.WrapStr("listening", err)
		}
		server := grpc.NewServer(libgrpc.UnaryServerInterceptor())
		sdpb.RegisterDaemonServiceServer(server, servers.DaemonServer{
			Fetcher:      cfg.Fetcher,
			ASInspector:  cfg.Engine.Inspector,
			RevCache:     cfg.RevCache,
			TopoProvider: itopo.Provider(),
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
		})
		return server.Serve(listener)
	}
}
