// Copyright 2018 ETH Zurich, Anapaya Systems
// Copyright 2025 SCION Association
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
	"io"
	"net"
	"strconv"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/daemon/grpc"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/asinfo"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/daemon/private/engine"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/private/drkey"
	"github.com/scionproto/scion/private/env"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/trust"
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

// ServerConfig is the configuration for the daemon API server.
type ServerConfig struct {
	IA          addr.IA
	MTU         uint16
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	Engine      trust.Engine
	LocalASInfo asinfo.LocalASInfo
	DRKeyClient *drkey.ClientEngine
}

// NewServer constructs a daemon API server.
func NewServer(cfg ServerConfig) *grpc.DaemonServer {
	return &grpc.DaemonServer{
		Engine: &engine.DaemonEngine{
			IA:  cfg.IA,
			MTU: cfg.MTU,
			// TODO(JordiSubira): This will be changed in the future to fetch
			// the information from the CS instead of feeding the configuration
			// file into.
			LocalASInfo: cfg.LocalASInfo,
			Fetcher:     cfg.Fetcher,
			ASInspector: cfg.Engine.Inspector,
			RevCache:    cfg.RevCache,
			DRKeyClient: cfg.DRKeyClient,
		},
		Metrics: grpc.Metrics{
			PathsRequests: grpc.RequestMetrics{
				Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
					Namespace: "sd",
					Subsystem: "path",
					Name:      "requests_total",
					Help:      "The amount of path requests received.",
				}, grpc.PathsRequestsLabels),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "path",
					Name:      "request_duration_seconds",
					Help:      "Time to handle path requests.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, grpc.LatencyLabels),
			},
			ASRequests: grpc.RequestMetrics{
				Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
					Namespace: "sd",
					Subsystem: "as_info",
					Name:      "requests_total",
					Help:      "The amount of AS requests received.",
				}, grpc.ASRequestsLabels),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "as_info",
					Name:      "request_duration_seconds",
					Help:      "Time to handle AS requests.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, grpc.LatencyLabels),
			},
			InterfacesRequests: grpc.RequestMetrics{
				Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
					Namespace: "sd",
					Subsystem: "if_info",
					Name:      "requests_total",
					Help:      "The amount of interfaces requests received.",
				}, grpc.InterfacesRequestsLabels),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "if_info",
					Name:      "request_duration_seconds",
					Help:      "Time to handle interfaces requests.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, grpc.LatencyLabels),
			},
			ServicesRequests: grpc.RequestMetrics{
				Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
					Namespace: "sd",
					Subsystem: "service_info",
					Name:      "requests_total",
					Help:      "The amount of services requests received.",
				}, grpc.ServicesRequestsLabels),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "service_info",
					Name:      "request_duration_seconds",
					Help:      "Time to handle services requests.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, grpc.LatencyLabels),
			},
			InterfaceDownNotifications: grpc.RequestMetrics{
				Requests: metrics.NewPromCounter(prom.SafeRegister(
					prometheus.NewCounterVec(prometheus.CounterOpts{
						Namespace: "sd",
						Name:      "received_revocations_total",
						Help:      "The amount of revocations received.",
					}, grpc.InterfaceDownNotificationsLabels)).(*prometheus.CounterVec),
				),
				Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
					Namespace: "sd",
					Subsystem: "revocation",
					Name:      "notification_duration_seconds",
					Help:      "Time to handle interface down notifications.",
					Buckets:   prom.DefaultLatencyBuckets,
				}, grpc.LatencyLabels),
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
		return net.JoinHostPort(listen, strconv.Itoa(daemon.DefaultAPIPort))
	case port == "0", port == "":
		return net.JoinHostPort(host, strconv.Itoa(daemon.DefaultAPIPort))
	default:
		return listen
	}
}
