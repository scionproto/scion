// Copyright 2019 Anapaya Systems
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

package metrics

import (
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/metrics"
)

// Metrics is the standard metrics used in periodic.Runner

// Deprecated: Metrics is used only in the deprecated function periodic.Start
// which exists only for compatibility reasons. Use periodic.StartWithMetrics
// along with periodic.Metrics instead.
type Metrics struct {
	Events    func(string) metrics.Counter
	Runtime   metrics.Gauge
	Timestamp metrics.Gauge
	Period    metrics.Gauge
}

func NewMetric(prefix string) Metrics {
	namespace := strcase.ToSnake(strings.Replace(prefix, ".", "_", -1))
	subsystem := "periodic"

	events := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "event_total",
		Help:      "Total number of events.",
	},
		[]string{"event_type"},
	)

	runtime := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "runtime_duration_seconds_total",
		Help:      "Total time spend on every periodic run.",
	},
		[]string{},
	)

	timestamp := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "runtime_timestamp_seconds",
		Help:      "The unix timestamp when the periodic run started.",
	},
		[]string{},
	)
	period := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "period_duration_seconds",
		Help:      "The period of this job.",
	},
		[]string{},
	)

	return Metrics{
		Events: func(s string) metrics.Counter {
			return metrics.NewPromCounter(events).With("event_type", s)
		},
		Runtime:   metrics.NewPromGauge(runtime),
		Timestamp: metrics.NewPromGauge(timestamp),
		Period:    metrics.NewPromGauge(period),
	}
}
