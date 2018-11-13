// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package prom contains some utility functions for dealing with prometheus
// metrics.
package prom

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func CopyLabels(labels prometheus.Labels) prometheus.Labels {
	l := make(prometheus.Labels)
	for k, v := range labels {
		l[k] = v
	}
	return l
}

// NewCounter creates a new prometheus counter that is registered with the default registry.
func NewCounter(namespace, subsystem, name, help string,
	constLabels prometheus.Labels) prometheus.Counter {
	return promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
		},
	)
}

// NewCounterVec creates a new prometheus counter vec that is registered with the default registry.
func NewCounterVec(namespace, subsystem, name, help string,
	constLabels prometheus.Labels, labelNames []string) *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
		},
		labelNames,
	)
}

// NewGauge creates a new prometheus gauge that is registered with the default registry.
func NewGauge(namespace, subsystem, name, help string,
	constLabels prometheus.Labels) prometheus.Gauge {
	return promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
		},
	)
}

// NewGaugeVec creates a new prometheus gauge vec that is registered with the default registry.
func NewGaugeVec(namespace, subsystem, name, help string,
	constLabels prometheus.Labels, labelNames []string) *prometheus.GaugeVec {
	return promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
		},
		labelNames,
	)
}

// NewHistogramVec creates a new prometheus histogram vec
// that is registered with the default registry.
func NewHistogramVec(namespace, subsystem, name, help string, constLabels prometheus.Labels,
	labelNames []string, buckets []float64) *prometheus.HistogramVec {
	return promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
			Buckets:     buckets,
		},
		labelNames,
	)
}
