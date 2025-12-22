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

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/daemon/drkey"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/daemon/server"

	"github.com/scionproto/scion/daemon/internal/servers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
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
	Topology    server.Topology
	DRKeyClient *drkey.ClientEngine
}

// NewServer constructs a daemon API server.
func NewServer(cfg ServerConfig) *servers.DaemonServer {
	return &servers.DaemonServer{
		Connector: &server.ConnectorMetricsWrapper{
			Connector: &server.ConnectorBackend{
				IA:  cfg.IA,
				MTU: cfg.MTU,
				// TODO(JordiSubira): This will be changed in the future to fetch
				// the information from the CS instead of feeding the configuration
				// file into.
				Topology:    cfg.Topology,
				Fetcher:     cfg.Fetcher,
				RevCache:    cfg.RevCache,
				DRKeyClient: cfg.DRKeyClient,
			},
			Metrics: &server.Metrics{
				PathsRequests: server.RequestMetrics{
					Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
						Namespace: "sd",
						Subsystem: "path",
						Name:      "requests_total",
						Help:      "The amount of path requests received.",
					}, server.PathsRequestsLabels),
					Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
						Namespace: "sd",
						Subsystem: "path",
						Name:      "request_duration_seconds",
						Help:      "Time to handle path requests.",
						Buckets:   prom.DefaultLatencyBuckets,
					}, server.LatencyLabels),
				},
				ASRequests: server.RequestMetrics{
					Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
						Namespace: "sd",
						Subsystem: "as_info",
						Name:      "requests_total",
						Help:      "The amount of AS requests received.",
					}, server.ASRequestsLabels),
					Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
						Namespace: "sd",
						Subsystem: "as_info",
						Name:      "request_duration_seconds",
						Help:      "Time to handle AS requests.",
						Buckets:   prom.DefaultLatencyBuckets,
					}, server.LatencyLabels),
				},
				InterfacesRequests: server.RequestMetrics{
					Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
						Namespace: "sd",
						Subsystem: "if_info",
						Name:      "requests_total",
						Help:      "The amount of interfaces requests received.",
					}, server.InterfacesRequestsLabels),
					Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
						Namespace: "sd",
						Subsystem: "if_info",
						Name:      "request_duration_seconds",
						Help:      "Time to handle interfaces requests.",
						Buckets:   prom.DefaultLatencyBuckets,
					}, server.LatencyLabels),
				},
				ServicesRequests: server.RequestMetrics{
					Requests: metrics.NewPromCounterFrom(prometheus.CounterOpts{
						Namespace: "sd",
						Subsystem: "service_info",
						Name:      "requests_total",
						Help:      "The amount of services requests received.",
					}, server.ServicesRequestsLabels),
					Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
						Namespace: "sd",
						Subsystem: "service_info",
						Name:      "request_duration_seconds",
						Help:      "Time to handle services requests.",
						Buckets:   prom.DefaultLatencyBuckets,
					}, server.LatencyLabels),
				},
				InterfaceDownNotifications: server.RequestMetrics{
					Requests: metrics.NewPromCounter(prom.SafeRegister(
						prometheus.NewCounterVec(prometheus.CounterOpts{
							Namespace: "sd",
							Name:      "received_revocations_total",
							Help:      "The amount of revocations received.",
						}, server.InterfaceDownNotificationsLabels)).(*prometheus.CounterVec),
					),
					Latency: metrics.NewPromHistogramFrom(prometheus.HistogramOpts{
						Namespace: "sd",
						Subsystem: "revocation",
						Name:      "notification_duration_seconds",
						Help:      "Time to handle interface down notifications.",
						Buckets:   prom.DefaultLatencyBuckets,
					}, server.LatencyLabels),
				},
			},
		},
		ASInspector: cfg.Engine.Inspector,
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
