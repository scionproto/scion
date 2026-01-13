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

package router

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// processingMetricsEnabled is a compile-time constant used for dead code elimination.
// Without the router_profile build tag, this constant is false.
//
// The Go compiler performs dead code elimination on `if false { ... }` blocks,
// completely removing them from the binary. This means:
//   - No defer registration overhead
//   - No time.Now() calls
//   - No function call overhead
//   - Zero runtime cost in production builds
//
// Verify with: go build -gcflags="-m" ./router/...
// (dead code blocks will not appear in the output)
const processingMetricsEnabled = false

func initProcessingMetrics() (*prometheus.HistogramVec, *prometheus.CounterVec) {
	return nil, nil
}

// These functions exist only for type checking. With processingMetricsEnabled=false,
// all calls are guarded by `if processingMetricsEnabled` and eliminated by the compiler.

func (m *Metrics) observeDuration(_ string, _ time.Time) {}
func (m *Metrics) incResult(_ string)                    {}
