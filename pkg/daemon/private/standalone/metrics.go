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

package standalone

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Metrics contains metrics for all StandaloneDaemon operations.
type Metrics struct {
	LocalIA       RequestMetric
	PortRange     RequestMetric
	Interfaces    RequestMetric
	Paths         PathRequestMetrics
	ASInfo        RequestMetric
	SVCInfo       RequestMetric
	InterfaceDown RequestMetric
	DRKeyASHost   RequestMetric
	DRKeyHostAS   RequestMetric
	DRKeyHostHost RequestMetric
}

// RequestMetric contains the metrics for a given request type.
type RequestMetric struct {
	Requests func(result string) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

func (m RequestMetric) Observe(err error, latency time.Duration) {
	result := standaloneResultFromErr(err)
	if m.Requests != nil {
		metrics.CounterInc(m.Requests(result))
	}
	if m.Latency != nil {
		metrics.HistogramObserve(m.Latency(result), float64(latency.Seconds()))
	}
}

type PathRequestMetrics struct {
	Requests func(result string, dst addr.ISD) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

func (m PathRequestMetrics) Observe(err error, dstISD addr.ISD, latency time.Duration) {
	result := standaloneResultFromErr(err)
	if m.Requests != nil {
		metrics.CounterInc(m.Requests(result, dstISD))
	}
	if m.Latency != nil {
		metrics.HistogramObserve(m.Latency(result), float64(latency.Seconds()))
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

// NewMetrics creates metrics for StandaloneDaemon operations.
func NewMetrics(opts ...metrics.Option) Metrics {
	auto := metrics.ApplyOptions(opts...).Auto()
	pathReq := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "standalone_daemon_paths_requests_total",
		Help: "The amount of path requests.",
	}, []string{prom.LabelResult, prom.LabelDst})
	pathLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "standalone_daemon_paths_request_duration_seconds",
		Help:    "Time to handle path requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})
	return Metrics{
		LocalIA:    newRequestMetric(auto, "local_ia", "local IA"),
		PortRange:  newRequestMetric(auto, "port_range", "port range"),
		Interfaces: newRequestMetric(auto, "interfaces", "interfaces"),
		Paths: PathRequestMetrics{
			Requests: func(result string, dst addr.ISD) metrics.Counter {
				return pathReq.With(prometheus.Labels{prom.LabelResult: result, prom.LabelDst: dst.String()})
			},
			Latency: func(result string) metrics.Histogram {
				return pathLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		ASInfo:  newRequestMetric(auto, "as_info", "AS info"),
		SVCInfo: newRequestMetric(auto, "svc_info", "SVC info"),
		InterfaceDown: newRequestMetric(
			auto, "interface_down", "interface down notification",
		),
		DRKeyASHost:   newRequestMetric(auto, "drkey_as_host", "DRKey AS-Host"),
		DRKeyHostAS:   newRequestMetric(auto, "drkey_host_as", "DRKey Host-AS"),
		DRKeyHostHost: newRequestMetric(auto, "drkey_host_host", "DRKey Host-Host"),
	}
}

func newRequestMetric(auto metrics.Factory, subsystem, description string) RequestMetric {
	requests := auto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "standalone_daemon",
			Subsystem: subsystem,
			Name:      "requests_total",
			Help:      "The amount of " + description + " requests.",
		},
		[]string{prom.LabelResult},
	)
	latency := auto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "standalone_daemon",
			Subsystem: subsystem,
			Name:      "request_duration_seconds",
			Help:      "Time to handle " + description + " requests.",
			Buckets:   prom.DefaultLatencyBuckets,
		},
		[]string{prom.LabelResult},
	)
	return RequestMetric{
		Requests: func(result string) metrics.Counter {
			return requests.With(prometheus.Labels{prom.LabelResult: result})
		},
		Latency: func(result string) metrics.Histogram {
			return latency.With(prometheus.Labels{prom.LabelResult: result})
		},
	}
}
