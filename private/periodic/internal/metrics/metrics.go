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
	"time"

	"github.com/iancoleman/strcase"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/metrics"
)

// ExportMetric is the interface to export periodic metrics.
type ExportMetric interface {
	Runtime(time.Duration)
	StartTimestamp(time.Time)
	Period(time.Duration)
	Event(string)
}

// NewMetric returns the ExportMetric to be used for the exporting metrics.
func NewMetric(prefix string) exporter {
	return newExporter(prefix)
}

type exporter struct {
	events    func(string) metrics.Counter
	runtime   metrics.Gauge
	timestamp metrics.Gauge
	period    metrics.Gauge
}

func newExporter(prefix string) exporter {
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

	return exporter{
		events: func(s string) metrics.Counter {
			return metrics.NewPromCounter(events).With("event_type", s)
		},
		runtime:   metrics.NewPromGauge(runtime),
		timestamp: metrics.NewPromGauge(timestamp),
		period:    metrics.NewPromGauge(period),
	}
}

func (e exporter) GetEvents() func(string) metrics.Counter {
	return e.events
}
func (e exporter) GetTimestamp() metrics.Gauge {
	return e.timestamp
}
func (e exporter) GetPeriod() metrics.Gauge {
	return e.period
}
func (e exporter) GetRuntime() metrics.Gauge {
	return e.runtime
}
