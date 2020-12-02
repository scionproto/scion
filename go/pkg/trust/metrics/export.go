// Copyright 2020 Anapaya Systems
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

// Exported metrics. This is a transitional hack until the new metrics approach
// is used everywhere.
var (
	RPC            = metrics.RPC
	CacheHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustengine_cache_lookups_total",
			Help: "Total number of cache hits in the trust engine.",
		},
		[]string{"type", prom.LabelResult},
	)
)
