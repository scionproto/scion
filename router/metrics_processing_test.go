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

// Tests for processing metrics. Only run when built with -tags router_profile:
//   go test -tags router_profile ./router/... -v -run TestProcess

package router

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// TestProcessingMetricsSchema verifies the metric schema without using the global registry.
// This avoids "duplicate metrics collector registration" errors from promauto.
func TestProcessingMetricsSchema(t *testing.T) {
	registry := prometheus.NewRegistry()

	// Create metrics with same schema as production
	processDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "router_process_duration_seconds",
			Help:    "Time spent processing packets by stage",
			Buckets: []float64{.000001, .000005, .00001, .00005, .0001, .0005, .001, .005, .01},
		},
		[]string{"stage"},
	)
	processResult := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "router_process_result_total",
			Help: "Packets processed by result",
		},
		[]string{"result"},
	)

	require.NoError(t, registry.Register(processDuration))
	require.NoError(t, registry.Register(processResult))

	// Verify all stage labels work
	processDuration.WithLabelValues("total").Observe(0.001)
	processDuration.WithLabelValues("parse").Observe(0.0001)
	processDuration.WithLabelValues("mac_verify").Observe(0.0002)
	processDuration.WithLabelValues("forward").Observe(0.0003)

	// Verify all result labels work
	processResult.WithLabelValues("forwarded").Inc()
	processResult.WithLabelValues("delivered").Inc()
	processResult.WithLabelValues("mac_failed").Inc()
}

func TestProcessingMetricsEnabledConstant(t *testing.T) {
	require.True(t, processingMetricsEnabled,
		"processingMetricsEnabled should be true when built with router_profile tag")
}

func TestObserveDurationMethod(t *testing.T) {
	// Test the helper method signature compiles and is callable
	// Note: We can't call NewMetrics() here due to global registry conflicts,
	// but we verify the method exists and the constant is set correctly.
	if !processingMetricsEnabled {
		t.Skip("processingMetricsEnabled is false - test requires router_profile tag")
	}

	// Create a minimal Metrics struct with test metrics
	registry := prometheus.NewRegistry()
	pd := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_duration",
			Buckets: []float64{.001, .01, .1},
		},
		[]string{"stage"},
	)
	registry.MustRegister(pd)

	m := &Metrics{ProcessDuration: pd}
	start := time.Now()
	time.Sleep(1 * time.Millisecond)
	m.observeDuration("test", start)
}
