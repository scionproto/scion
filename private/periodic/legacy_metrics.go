package periodic

import (
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/prometheus/client_golang/prometheus"
)

// newLegacyMetrics creates the metrics for the deprecated Start function. It
// uses the same old metrics as prior to the introduction of the
// StartWithMetrics function.
func newLegacyMetrics(prefix string) Metrics {
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

	runtime := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "runtime_duration_seconds_total",
		Help:      "Total time spend on every periodic run.",
	})

	timestamp := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "runtime_timestamp_seconds",
		Help:      "The unix timestamp when the periodic run started.",
	})
	period := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "period_duration_seconds",
		Help:      "The period of this job.",
	})

	return Metrics{
		StopEvents:    events.With(prometheus.Labels{"event_type": "stop"}),
		KillEvents:    events.With(prometheus.Labels{"event_type": "kill"}),
		TriggerEvents: events.With(prometheus.Labels{"event_type": "trigger"}),
		Runtime:       runtime,
		StartTime:     timestamp,
		Period:        period,
	}
}
