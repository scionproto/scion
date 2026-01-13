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

//go:build router_profile

package router

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// processingMetricsEnabled is a compile-time constant that enables processing metrics.
// Build with: go build -tags router_profile
const processingMetricsEnabled = true

func initProcessingMetrics() (*prometheus.HistogramVec, *prometheus.CounterVec) {
	return promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "router_process_duration_seconds",
				Help:    "Time spent processing packets by stage (requires router_profile build tag)",
				Buckets: []float64{.000001, .000005, .00001, .00005, .0001, .0005, .001, .005, .01},
			},
			[]string{"stage"},
		),
		promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "router_process_result_total",
				Help: "Packets processed by result (requires router_profile build tag)",
			},
			[]string{"result"},
		)
}

// observeDuration records processing duration for a stage.
func (m *Metrics) observeDuration(stage string, start time.Time) {
	m.ProcessDuration.WithLabelValues(stage).Observe(time.Since(start).Seconds())
}

// incResult increments the result counter.
func (m *Metrics) incResult(result string) {
	m.ProcessResult.WithLabelValues(result).Inc()
}
