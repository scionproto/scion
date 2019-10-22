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

	"github.com/scionproto/scion/go/lib/prom"
)

const (
	// EventStop indicates a stop event took place.
	EventStop = "stop"
	// EventKill indicates a kill event took place.
	EventKill = "kill"
	// EventTrigger indicates a trigger event took place.
	EventTrigger = "triggered"
)

// ExportMetric is the interface to export periodic metrics.
type ExportMetric interface {
	Runtime(time.Duration)
	StartTimestamp(time.Time)
	Period(time.Duration)
	Event(string)
}

// NewMetric returns the ExportMetric to be used for the exporting metrics.
func NewMetric(prefix string) ExportMetric {
	return newExporter(prefix)
}

type exporter struct {
	events            *prometheus.CounterVec
	runtime           prometheus.Counter
	timestamp, period prometheus.Gauge
}

func newExporter(prefix string) exporter {
	namespace := strcase.ToSnake(strings.Replace(prefix, ".", "_", -1))
	subsystem := "periodic"

	events := prom.NewCounterVecWithLabels(namespace, subsystem, "event_total",
		"Total number of events.", EventLabels{EventTrigger})

	runtime := prom.SafeRegister(
		prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "runtime_duration_seconds_total",
			Help:      "Total time spend on every periodic run.",
		}),
	).(prometheus.Counter)

	timestamp := prom.SafeRegister(
		prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "runtime_timestamp_seconds",
			Help:      "The unix timestamp when the periodic run started.",
		}),
	).(prometheus.Gauge)

	period := prom.SafeRegister(
		prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "period_duration_seconds",
			Help:      "The period of this job.",
		}),
	).(prometheus.Gauge)

	return exporter{
		events:    events,
		runtime:   runtime,
		timestamp: timestamp,
		period:    period,
	}
}

func (e exporter) StartTimestamp(t time.Time) {
	e.timestamp.Set(float64(t.UnixNano() / 1e9))
}

func (e exporter) Period(d time.Duration) {
	e.period.Set(d.Seconds())
}

func (e exporter) Runtime(d time.Duration) {
	e.runtime.Add(float64(d) / 1e9)
}

func (e exporter) Event(s string) {
	l := EventLabels{s}
	e.events.WithLabelValues(l.Values()...).Inc()
}

// EventLabels is used by clients to pass in a safe way labels
// values to prometheus metric types (e.g. counter).
type EventLabels struct {
	eventType string
}

// Labels returns the name of the labels in correct order.
func (l EventLabels) Labels() []string {
	return []string{"event_type"}
}

// Values returns the values of the label in correct order.
func (l EventLabels) Values() []string {
	return []string{l.eventType}
}
