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

	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Metrics contains metrics for all StandaloneDaemon operations.
type Metrics struct {
	LocalIA       RequestMetric
	PortRange     RequestMetric
	Interfaces    RequestMetric
	Paths         RequestMetric
	ASInfo        RequestMetric
	SVCInfo       RequestMetric
	InterfaceDown RequestMetric
	DRKeyASHost   RequestMetric
	DRKeyHostAS   RequestMetric
	DRKeyHostHost RequestMetric
}

// RequestMetric contains the metrics for a given request type.
type RequestMetric struct {
	Requests metrics.Counter
	Latency  metrics.Histogram
}

func (m RequestMetric) Observe(err error, latency time.Duration, extraLabels ...string) {
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
func NewStandaloneMetrics() Metrics {
	resultLabels := []string{prom.LabelResult}
	pathLabels := []string{prom.LabelResult, prom.LabelDst}
	return Metrics{
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

func newRequestMetric(subsystem, description string, labels []string) RequestMetric {
	return RequestMetric{
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
