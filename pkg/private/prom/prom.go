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

// Common label values.
const (
	// LabelResult is the label for result classifications.
	LabelResult = "result"
	// LabelStatus for latency status classifications, possible values are prefixed with Status*.
	LabelStatus = "status"
	// LabelOperation is the label for the name of an executed operation.
	LabelOperation = "op"
	// LabelSrc is the label for the source.
	LabelSrc = "src"
	// LabelDst is the label for the destination.
	LabelDst = "dst"
	// LabelNeighIA is label for the neighboring IA.
	LabelNeighIA = "neighbor_isd_as"
)

// Common result values.
const (
	// Success is no error.
	Success = "ok_success"
	// ErrCrypto is used for crypto related errors.
	ErrCrypto = "err_crypto"
	// ErrDB is used for db related errors.
	ErrDB = "err_db"
	// ErrInternal is an internal error.
	ErrInternal = "err_internal"
	// ErrInvalidReq is an invalid request.
	ErrInvalidReq = "err_invalid_request"
	// ErrNotClassified is an error that is not further classified.
	ErrNotClassified = "err_not_classified"
	// ErrParse failed to parse request.
	ErrParse = "err_parse"
	// ErrProcess is an error during processing e.g. parsing failed.
	ErrProcess = "err_process"
	// ErrTimeout is a timeout error.
	ErrTimeout = "err_timeout"
	// ErrValidate is used for validation related errors.
	ErrValidate = "err_validate"
	// ErrVerify is used for verification related errors.
	ErrVerify = "err_verify"
	// ErrNetwork is used for errors when sending something over the network.
	ErrNetwork = "err_network"
	// ErrNotFound is used for errors where a resource is not found.
	ErrNotFound = "err_not_found"
	// ErrUnavailable is used for errors where a resource is not available.
	ErrUnavailable = "err_unavailable"
)

// FIXME(roosd): remove when moving messenger to new metrics style.
const (
	StatusErr     = "err"
	StatusTimeout = "err_timeout"
)

var (
	// DefaultLatencyBuckets 10ms, 20ms, 40ms, ... 5.12s, 10.24s.
	DefaultLatencyBuckets = []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64,
		1.28, 2.56, 5.12, 10.24}
	// DefaultSizeBuckets 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
	DefaultSizeBuckets = []float64{32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}
)

// Labels allows to safely pass label values into prometheus.
type Labels interface {
	Labels() []string
	Values() []string
}

// ExportElementID exports the element ID as configured in the config file.
func ExportElementID(id string) {
	promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "scion",
			Subsystem: "",
			Name:      "elem_id",
			Help:      "The element ID from the config file",
		},
		[]string{"cfg"},
	).WithLabelValues(id).Set(1)
}

// SafeRegister registers c and returns the registered collector. If c was
// already registered the already registered collector is returned. In case of
// any other error this method panicks (as MustRegister).
func SafeRegister(c prometheus.Collector) prometheus.Collector {
	if err := prometheus.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			return are.ExistingCollector
		}
		panic(err)
	}
	return c
}

// NewCounter creates a new prometheus counter that is registered with the default registry.
func NewCounter(namespace, subsystem, name, help string) prometheus.Counter {
	return promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      name,
			Help:      help,
		},
	)
}

// NewCounterVecWithLabels creates a prometheus counter vec that is registered with
// the default registry and with a default init values for labels to avoid missing metrics.
func NewCounterVecWithLabels(ns, sub, name, help string, label Labels) *prometheus.CounterVec {
	opts := prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      name,
		Help:      help,
	}
	c := prometheus.NewCounterVec(opts, label.Labels())
	ret := SafeRegister(c).(*prometheus.CounterVec)
	return ret
}

// NewCounterVec creates a new prometheus counter vec that is registered with the default registry.
func NewCounterVec(namespace, subsystem, name, help string,
	labelNames []string) *prometheus.CounterVec {
	// Not to be used https://github.com/scionproto/scion/issues/3274

	return NewCounterVecWithLabels(namespace, subsystem, name, help,
		initLabels{labelNames: labelNames})
}

// NewGauge creates a new prometheus gauge that is registered with the default registry.
func NewGauge(namespace, subsystem, name, help string) prometheus.Gauge {
	return promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      name,
			Help:      help,
		},
	)
}

// NewGaugeVecWithLabels creates a new prometheus gauge vec that is registered
// with the default registry.
func NewGaugeVecWithLabels(namespace, subsystem, name, help string,
	label Labels) *prometheus.GaugeVec {
	opts := prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
	}

	c := prometheus.NewGaugeVec(opts, label.Labels())
	ret := SafeRegister(c).(*prometheus.GaugeVec)
	return ret
}

// NewGaugeVec creates a new prometheus gauge vec that is registered with the default registry.
func NewGaugeVec(namespace, subsystem, name, help string,
	labelNames []string) *prometheus.GaugeVec {
	// Not to be used https://github.com/scionproto/scion/issues/3274

	return NewGaugeVecWithLabels(namespace, subsystem, name, help,
		initLabels{labelNames: labelNames})
}

// NewHistogram creates a new prometheus histogram that is registered with the default registry.
func NewHistogram(namespace, subsystem, name, help string, buckets []float64) prometheus.Histogram {
	return promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      name,
			Help:      help,
			Buckets:   buckets,
		},
	)
}

// NewHistogramVecWithLabels creates a new prometheus histogram vec
// that is registered with the default registry.
func NewHistogramVecWithLabels(namespace, subsystem, name, help string,
	label Labels, buckets []float64) *prometheus.HistogramVec {

	opts := prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
		Buckets:   buckets,
	}

	c := prometheus.NewHistogramVec(opts, label.Labels())
	ret := SafeRegister(c).(*prometheus.HistogramVec)
	return ret
}

// NewHistogramVec creates a new prometheus histogram vec
// that is registered with the default registry.
func NewHistogramVec(namespace, subsystem, name, help string,
	labelNames []string, buckets []float64) *prometheus.HistogramVec {
	// Not to be used https://github.com/scionproto/scion/issues/3274

	return NewHistogramVecWithLabels(namespace, subsystem, name, help,
		initLabels{labelNames: labelNames}, buckets)
}

type initLabels struct {
	labelNames []string
}

func (l initLabels) Labels() []string {
	return l.labelNames
}

func (l initLabels) Values() []string {
	return nil
}
