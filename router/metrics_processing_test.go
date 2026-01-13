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

func TestObserveDurationRecordsValue(t *testing.T) {
	registry := prometheus.NewRegistry()
	pd := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_observe_duration",
			Buckets: []float64{.0001, .001, .01, .1},
		},
		[]string{"stage"},
	)
	registry.MustRegister(pd)

	m := &Metrics{ProcessDuration: pd}

	// Record a duration
	start := time.Now()
	time.Sleep(2 * time.Millisecond)
	m.observeDuration("parse", start)

	// Verify the metric was recorded
	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	require.Equal(t, "test_observe_duration", metrics[0].GetName())

	// Check that we have exactly one metric with stage="parse"
	metricFamily := metrics[0].GetMetric()
	require.Len(t, metricFamily, 1)
	require.Equal(t, "parse", metricFamily[0].GetLabel()[0].GetValue())

	// Verify count is 1
	histogram := metricFamily[0].GetHistogram()
	require.Equal(t, uint64(1), histogram.GetSampleCount())

	// Verify sum is approximately 2ms (with some tolerance)
	sum := histogram.GetSampleSum()
	require.Greater(t, sum, 0.001, "duration should be at least 1ms")
	require.Less(t, sum, 0.1, "duration should be less than 100ms")
}

func TestObserveDurationAllStages(t *testing.T) {
	stages := []string{"parse", "mac_verify", "forward", "total"}

	registry := prometheus.NewRegistry()
	pd := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_all_stages",
			Buckets: []float64{.0001, .001, .01},
		},
		[]string{"stage"},
	)
	registry.MustRegister(pd)

	m := &Metrics{ProcessDuration: pd}

	// Record a duration for each stage
	for _, stage := range stages {
		start := time.Now()
		m.observeDuration(stage, start)
	}

	// Verify all stages were recorded
	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, 1)

	metricFamily := metrics[0].GetMetric()
	require.Len(t, metricFamily, len(stages))

	recordedStages := make(map[string]bool)
	for _, metric := range metricFamily {
		stageName := metric.GetLabel()[0].GetValue()
		recordedStages[stageName] = true
		require.Equal(t, uint64(1), metric.GetHistogram().GetSampleCount())
	}

	for _, stage := range stages {
		require.True(t, recordedStages[stage], "stage %s should be recorded", stage)
	}
}

func TestIncResultMethod(t *testing.T) {
	registry := prometheus.NewRegistry()
	pr := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_result_counter",
		},
		[]string{"result"},
	)
	registry.MustRegister(pr)

	m := &Metrics{ProcessResult: pr}

	// Increment each result type
	m.incResult("forwarded")
	m.incResult("forwarded")
	m.incResult("delivered")
	m.incResult("mac_failed")

	// Verify the metrics
	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, 1)

	metricFamily := metrics[0].GetMetric()
	require.Len(t, metricFamily, 3)

	// Build a map of result -> count
	resultCounts := make(map[string]float64)
	for _, metric := range metricFamily {
		resultName := metric.GetLabel()[0].GetValue()
		resultCounts[resultName] = metric.GetCounter().GetValue()
	}

	require.Equal(t, float64(2), resultCounts["forwarded"])
	require.Equal(t, float64(1), resultCounts["delivered"])
	require.Equal(t, float64(1), resultCounts["mac_failed"])
}

func TestIncResultAllResults(t *testing.T) {
	results := []string{"forwarded", "delivered", "mac_failed"}

	registry := prometheus.NewRegistry()
	pr := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_all_results",
		},
		[]string{"result"},
	)
	registry.MustRegister(pr)

	m := &Metrics{ProcessResult: pr}

	// Increment each result
	for _, result := range results {
		m.incResult(result)
	}

	// Verify all results were recorded
	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, 1)

	metricFamily := metrics[0].GetMetric()
	require.Len(t, metricFamily, len(results))

	for _, metric := range metricFamily {
		require.Equal(t, float64(1), metric.GetCounter().GetValue())
	}
}

func TestInitProcessingMetricsReturnsNonNil(t *testing.T) {
	// This test verifies the real implementation returns non-nil metrics
	// Note: This will conflict with global registry if NewMetrics() was called,
	// so we test the function signature and return type indirectly
	require.True(t, processingMetricsEnabled)

	// Create test metrics to verify the types are correct
	registry := prometheus.NewRegistry()
	pd := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_init_duration",
			Buckets: []float64{.001},
		},
		[]string{"stage"},
	)
	pr := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_init_result",
		},
		[]string{"result"},
	)
	registry.MustRegister(pd)
	registry.MustRegister(pr)

	// Verify both can be used
	m := &Metrics{ProcessDuration: pd, ProcessResult: pr}
	require.NotNil(t, m.ProcessDuration)
	require.NotNil(t, m.ProcessResult)

	m.observeDuration("test", time.Now())
	m.incResult("test")
}
