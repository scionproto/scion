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
	kitprom "github.com/go-kit/kit/metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
)

// NewPromGauge wraps a prometheus gauge vector as a gauge.
func NewPromGauge(cv *prometheus.GaugeVec) Gauge {
	return kitprom.NewGauge(cv)
}

// NewPromCounter wraps a prometheus counter vector as a counter.
func NewPromCounter(cv *prometheus.CounterVec) Counter {
	return kitprom.NewCounter(cv)
}

// NewPromCounterFrom creates a wrapped prometheus counter.
func NewPromCounterFrom(opts prometheus.CounterOpts, labelNames []string) Counter {
	return kitprom.NewCounterFrom(opts, labelNames)
}

// NewPromHistogramFrom creates a wrapped prometheus histogram.
func NewPromHistogramFrom(opts prometheus.HistogramOpts, labelNames []string) Histogram {
	return kitprom.NewHistogramFrom(opts, labelNames)
}
