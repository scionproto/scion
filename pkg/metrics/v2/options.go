// Copyright 2026 Anapaya Systems
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
)

type Option func(*Options)

// Options configures the metrics Factory, construct it using the ApplyOptions
// function.
type Options struct {
	registry            prometheus.Registerer
	collectorCustomizer func(string, prometheus.Collector) prometheus.Collector
}

func (o Options) registerer() prometheus.Registerer {
	if o.registry != nil {
		return o.registry
	}
	return prometheus.DefaultRegisterer
}

// WithCollectorCustomizer sets a customizer function that is called for each
// collector before it is registered. The function receives the fully qualified
// name of the collector and the collector itself, and must return the collector
// to be registered (which can be the same as the input collector or a wrapped
// version).
func WithCollectorCustomizer(
	customizer func(string, prometheus.Collector) prometheus.Collector,
) Option {
	return func(o *Options) {
		o.collectorCustomizer = customizer
	}
}

func WithRegistry(registry prometheus.Registerer) Option {
	return func(o *Options) {
		o.registry = registry
	}
}

func ApplyOptions(options ...Option) Options {
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}
	return opts
}

// Auto creates a Factory that uses the provided Options as registry. If no
// explicit registry is set the default registry is used.
func (o Options) Auto() Factory {
	return Factory{opts: o}
}

// Factory is a metrics Factory that registers metrics using the provided
// Options. Construct it using the Options.Auto function.
type Factory struct {
	opts Options
}

func (f Factory) register(fqName string, c prometheus.Collector) {
	reg := f.opts.registerer()
	if f.opts.collectorCustomizer != nil {
		c = f.opts.collectorCustomizer(fqName, c)
	}
	reg.MustRegister(c)
}

func (f Factory) NewCounter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), c)
	return c
}

func (f Factory) NewCounterVec(
	opts prometheus.CounterOpts,
	labelNames []string,
) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labelNames)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), c)
	return c
}

func (f Factory) NewCounterFunc(
	opts prometheus.CounterOpts,
	function func() float64,
) prometheus.CounterFunc {
	c := prometheus.NewCounterFunc(opts, function)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), c)
	return c
}

func (f Factory) NewGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(opts)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), g)
	return g
}

func (f Factory) NewGaugeVec(opts prometheus.GaugeOpts, labelNames []string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(opts, labelNames)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), g)
	return g
}

func (f Factory) NewGaugeFunc(
	opts prometheus.GaugeOpts,
	function func() float64,
) prometheus.GaugeFunc {
	g := prometheus.NewGaugeFunc(opts, function)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), g)
	return g
}

func (f Factory) NewSummary(opts prometheus.SummaryOpts) prometheus.Summary {
	s := prometheus.NewSummary(opts)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), s)
	return s
}

func (f Factory) NewSummaryVec(
	opts prometheus.SummaryOpts,
	labelNames []string,
) *prometheus.SummaryVec {
	s := prometheus.NewSummaryVec(opts, labelNames)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), s)
	return s
}

func (f Factory) NewHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	h := prometheus.NewHistogram(opts)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), h)
	return h
}

func (f Factory) NewHistogramVec(
	opts prometheus.HistogramOpts,
	labelNames []string,
) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(opts, labelNames)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), h)
	return h
}

func (f Factory) NewUntypedFunc(
	opts prometheus.UntypedOpts,
	function func() float64,
) prometheus.UntypedFunc {
	u := prometheus.NewUntypedFunc(opts, function)
	f.register(prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name), u)
	return u
}
