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

//go:build !router_profile

// Tests for processing metrics stub. These run in normal builds (without router_profile tag)
// to verify the stub implementation works correctly and has zero overhead.

package router

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStubProcessingMetricsDisabled(t *testing.T) {
	require.False(t, processingMetricsEnabled,
		"processingMetricsEnabled should be false when built without router_profile tag")
}

func TestStubInitProcessingMetricsReturnsNil(t *testing.T) {
	pd, pr := initProcessingMetrics()
	require.Nil(t, pd, "ProcessDuration should be nil in stub")
	require.Nil(t, pr, "ProcessResult should be nil in stub")
}

func TestStubObserveDurationNoOp(t *testing.T) {
	// Verify that calling observeDuration on a Metrics with nil ProcessDuration
	// does not panic. This is the stub behavior.
	m := &Metrics{
		ProcessDuration: nil,
		ProcessResult:   nil,
	}

	// This should be a no-op and not panic
	start := time.Now()
	m.observeDuration("parse", start)
	m.observeDuration("mac_verify", start)
	m.observeDuration("forward", start)
	m.observeDuration("total", start)
}

func TestStubIncResultNoOp(t *testing.T) {
	// Verify that calling incResult on a Metrics with nil ProcessResult
	// does not panic. This is the stub behavior.
	m := &Metrics{
		ProcessDuration: nil,
		ProcessResult:   nil,
	}

	// This should be a no-op and not panic
	m.incResult("forwarded")
	m.incResult("delivered")
	m.incResult("mac_failed")
}

func TestStubMetricsInNewMetrics(t *testing.T) {
	// When NewMetrics() is called without router_profile tag,
	// ProcessDuration and ProcessResult should be nil.
	// Note: We can't call NewMetrics() directly due to global registry,
	// but we verify the initProcessingMetrics behavior.
	pd, pr := initProcessingMetrics()
	require.Nil(t, pd)
	require.Nil(t, pr)
}

func TestStubZeroOverhead(t *testing.T) {
	// This test verifies that the stub implementation has minimal overhead.
	// The actual "zero overhead" comes from compiler dead code elimination,
	// but we verify the runtime behavior is correct.
	m := &Metrics{
		ProcessDuration: nil,
		ProcessResult:   nil,
	}

	// Run many iterations - should be essentially instant since it's a no-op
	iterations := 100000
	start := time.Now()
	for i := 0; i < iterations; i++ {
		m.observeDuration("total", start)
		m.incResult("forwarded")
	}
	elapsed := time.Since(start)

	// Should complete very quickly (less than 100ms for 100k iterations)
	// This is a sanity check, not a precise benchmark
	require.Less(t, elapsed, 100*time.Millisecond,
		"stub operations should be very fast")
}
