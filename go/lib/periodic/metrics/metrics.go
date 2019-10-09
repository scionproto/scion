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
	"time"

	"github.com/iancoleman/strcase"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

const (
	//EventStop indicates a stop event took place.
	EventStop = "stop"
	//EventKill indicates a kill event took place.
	EventKill = "kill"
	//EventTrigger indicates a trigger event took place.
	EventTrigger = "triggered"
)

var counters = make(map[string]exporter)

// NewMetric return a struct with the metrics counters.
var NewMetric = newMetric

// ExportMetric is the interface to export periodic metrics.
type ExportMetric interface {
	Runtime(time.Duration)
	StartTimestamp(time.Time)
	Period(time.Duration)
	Event(string)
}

type exporter struct {
	events            *prometheus.CounterVec
	runtime           prometheus.Counter
	timestamp, period prometheus.Gauge
}

func (e exporter) StartTimestamp(t time.Time) {
	e.timestamp.Set(float64(t.UnixNano() / 1e9))
}

func (e exporter) Period(d time.Duration) {
	e.period.Set(float64(d) / 1e9)
}

func (e exporter) Runtime(d time.Duration) {
	e.runtime.Add(float64(d) / 1e9)
}

func (e exporter) Event(s string) {
	l := EventLabels{s}
	e.events.WithLabelValues(l.Values()...).Inc()
}

func newMetric(prefix string) ExportMetric {
	key := strcase.ToSnake(prefix)
	if v, ok := counters[key]; ok {
		return v
	}

	sub := "periodic"
	ret := exporter{
		events: prom.NewCounterVec(key, sub, "event_total",
			"Total number of events.", EventLabels{}.Labels()),
		runtime: prom.NewCounter(key, sub, "runtime_duration_seconds_total",
			"Total time spend on every periodic run."),
		timestamp: prom.NewGauge(key, sub, "runtime_timestamp_seconds",
			"The unix timestamp when the periodic run started."),
		period: prom.NewGauge(key, sub, "period_duration_seconds",
			"The period of this job."),
	}

	counters[key] = ret

	return ret
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
