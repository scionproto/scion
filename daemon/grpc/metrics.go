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

package grpc

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Metrics can be used to inject metrics into the SCION daemon server. Each
// field may be set individually.
type Metrics struct {
	PathsRequests              PathRequestMetrics
	ASRequests                 RequestMetrics
	InterfacesRequests         RequestMetrics
	ServicesRequests           RequestMetrics
	InterfaceDownNotifications InterfaceDownNotificationMetrics
}

func NewMetrics(opts ...metrics.Option) Metrics {
	auto := metrics.ApplyOptions(opts...).Auto()
	pathRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_path_requests_total",
		Help: "The amount of path requests received.",
	}, []string{prom.LabelResult, prom.LabelDst})
	pathLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_path_request_duration_seconds",
		Help:    "Time to handle path requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	asRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_as_info_requests_total",
		Help: "The amount of AS requests received.",
	}, []string{prom.LabelResult})
	asLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_as_info_request_duration_seconds",
		Help:    "Time to handle AS requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	interfacesRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_if_info_requests_total",
		Help: "The amount of interfaces requests received.",
	}, []string{prom.LabelResult})
	interfacesLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_if_info_request_duration_seconds",
		Help:    "Time to handle interfaces requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	servicesRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_service_info_requests_total",
		Help: "The amount of services requests received.",
	}, []string{prom.LabelResult})
	servicesLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_service_info_request_duration_seconds",
		Help:    "Time to handle services requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	ifDownRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_received_revocations_total",
		Help: "The amount of revocations received.",
	}, []string{prom.LabelResult, prom.LabelSrc})
	ifDownLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_revocation_notification_duration_seconds",
		Help:    "Time to handle interface down notifications.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	return Metrics{
		PathsRequests: PathRequestMetrics{
			Requests: func(result string, dstISD addr.ISD) metrics.Counter {
				return pathRequests.With(prometheus.Labels{
					prom.LabelResult: result,
					prom.LabelDst:    dstISD.String(),
				})
			},
			Latency: func(result string) metrics.Histogram {
				return pathLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		ASRequests: RequestMetrics{
			Requests: func(result string) metrics.Counter {
				return asRequests.With(prometheus.Labels{prom.LabelResult: result})
			},
			Latency: func(result string) metrics.Histogram {
				return asLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		InterfacesRequests: RequestMetrics{
			Requests: func(result string) metrics.Counter {
				return interfacesRequests.With(prometheus.Labels{prom.LabelResult: result})
			},
			Latency: func(result string) metrics.Histogram {
				return interfacesLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		ServicesRequests: RequestMetrics{
			Requests: func(result string) metrics.Counter {
				return servicesRequests.With(prometheus.Labels{prom.LabelResult: result})
			},
			Latency: func(result string) metrics.Histogram {
				return servicesLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		InterfaceDownNotifications: InterfaceDownNotificationMetrics{
			Requests: func(result, src string) metrics.Counter {
				return ifDownRequests.With(prometheus.Labels{
					prom.LabelResult: result,
					prom.LabelSrc:    src,
				})
			},
			Latency: func(result string) metrics.Histogram {
				return ifDownLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
	}
}

// RequestMetrics contains the metrics for a given request.
type RequestMetrics struct {
	Requests func(result string) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

func (m RequestMetrics) inc(result string, latency float64) {
	if m.Requests != nil {
		metrics.CounterInc(m.Requests(result))
	}
	if m.Latency != nil {
		metrics.HistogramObserve(m.Latency(result), latency)
	}
}

type PathRequestMetrics struct {
	Requests func(result string, dstISD addr.ISD) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

func (m PathRequestMetrics) inc(result string, dstISD addr.ISD, latency float64) {
	if m.Requests != nil {
		metrics.CounterInc(m.Requests(result, dstISD))
	}
	if m.Latency != nil {
		metrics.HistogramObserve(m.Latency(result), latency)
	}
}

type InterfaceDownNotificationMetrics struct {
	Requests func(result, src string) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

func (m InterfaceDownNotificationMetrics) inc(result, src string, latency float64) {
	if m.Requests != nil {
		metrics.CounterInc(m.Requests(result, src))
	}
	if m.Latency != nil {
		metrics.HistogramObserve(m.Latency(result), latency)
	}
}

type metricsError struct {
	err    error
	result string
}

func (e metricsError) Error() string {
	return e.err.Error()
}

func errToMetricResult(err error) string {
	if err == nil {
		return prom.Success
	}
	if merr, ok := err.(metricsError); ok && merr.result != "" {
		if serrors.IsTimeout(merr.err) {
			return prom.ErrTimeout
		}
		return merr.result
	}
	if serrors.IsTimeout(err) {
		return prom.ErrTimeout
	}
	return prom.ErrNotClassified
}

func unwrapMetricsError(err error) error {
	if err == nil {
		return nil
	}
	if merr, ok := err.(metricsError); ok {
		return merr.err
	}
	return err
}
