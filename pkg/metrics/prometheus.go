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
)

// NewPromGauge wraps a prometheus gauge vector as a gauge.
// Returns nil, if gv is nil.
func NewPromGauge(gv *prometheus.GaugeVec) Gauge {
	if gv == nil {
		return nil
	}
	return newGauge(gv)
}

// NewPromCounter wraps a prometheus counter vector as a counter.
// Returns nil if cv is nil.
func NewPromCounter(cv *prometheus.CounterVec) Counter {
	if cv == nil {
		return nil
	}
	return newCounter(cv)
}

// NewPromHistogram wraps a prometheus histogram vector as a histogram.
// Returns nil if hv is nil.
func NewPromHistogram(hv *prometheus.HistogramVec) Histogram {
	if hv == nil {
		return nil
	}
	return newHistogram(hv)
}

// NewPromCounterFrom creates a wrapped prometheus counter.
func NewPromCounterFrom(opts prometheus.CounterOpts, labelNames []string) Counter {
	return newCounterFrom(opts, labelNames)
}

// NewPromHistogramFrom creates a wrapped prometheus histogram.
func NewPromHistogramFrom(opts prometheus.HistogramOpts, labelNames []string) Histogram {
	return newHistogramFrom(opts, labelNames)
}

// The types are taken from the metrics interfaces in the go-kit/kit project
// under the prometheus package. The code was slightly adapted to no longer
// expose the types. The code has the following license
//
// The MIT License (MIT)
//
// Copyright (c) 2015 Peter Bourgon
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// labelValuesSlice is a type alias that provides validation on its With method.
// Metrics may include it as a member to help them satisfy With semantics and
// save some code duplication.
type labelValuesSlice []string

// With validates the input, and returns a new aggregate labelValues.
func (lvs labelValuesSlice) With(labelValues ...string) labelValuesSlice {
	if len(labelValues)%2 != 0 {
		labelValues = append(labelValues, "unknown")
	}
	result := make(labelValuesSlice, len(lvs))
	copy(result, lvs)
	return append(result, labelValues...)
}

// gauge implements Gauge, via a Prometheus GaugeVec.
type gauge struct {
	gv  *prometheus.GaugeVec
	lvs labelValuesSlice
}

// With implements Gauge.
func (g *gauge) With(labelValues ...string) Gauge {
	return &gauge{
		gv:  g.gv,
		lvs: g.lvs.With(labelValues...),
	}
}

// Set implements Gauge.
func (g *gauge) Set(value float64) {
	g.gv.With(makeLabels(g.lvs...)).Set(value)
}

// Add is supported by Prometheus GaugeVecs.
func (g *gauge) Add(delta float64) {
	g.gv.With(makeLabels(g.lvs...)).Add(delta)
}

// newGauge wraps the GaugeVec and returns a usable Gauge object.
func newGauge(gv *prometheus.GaugeVec) *gauge {
	return &gauge{
		gv: gv,
	}
}

// counter implements Counter, via a Prometheus CounterVec.
type counter struct {
	cv  *prometheus.CounterVec
	lvs labelValuesSlice
}

// newCounterFrom constructs and registers a Prometheus CounterVec,
// and returns a usable Counter object.
func newCounterFrom(opts prometheus.CounterOpts, labelNames []string) *counter {
	cv := prometheus.NewCounterVec(opts, labelNames)
	prometheus.MustRegister(cv)
	return newCounter(cv)
}

// newCounter wraps the CounterVec and returns a usable Counter object.
func newCounter(cv *prometheus.CounterVec) *counter {
	return &counter{
		cv: cv,
	}
}

// With implements Counter.
func (c *counter) With(labelValues ...string) Counter {
	return &counter{
		cv:  c.cv,
		lvs: c.lvs.With(labelValues...),
	}
}

// Add implements Counter.
func (c *counter) Add(delta float64) {
	c.cv.With(makeLabels(c.lvs...)).Add(delta)
}

// histogram implements Histogram via a Prometheus HistogramVec. The difference
// between a Histogram and a Summary is that Histograms require predefined
// quantile buckets, and can be statistically aggregated.
type histogram struct {
	hv  *prometheus.HistogramVec
	lvs labelValuesSlice
}

// newHistogramFrom constructs and registers a Prometheus HistogramVec,
// and returns a usable Histogram object.
func newHistogramFrom(opts prometheus.HistogramOpts, labelNames []string) *histogram {
	hv := prometheus.NewHistogramVec(opts, labelNames)
	prometheus.MustRegister(hv)
	return newHistogram(hv)
}

// newHistogram wraps the HistogramVec and returns a usable Histogram object.
func newHistogram(hv *prometheus.HistogramVec) *histogram {
	return &histogram{
		hv: hv,
	}
}

// With implements Histogram.
func (h *histogram) With(labelValues ...string) Histogram {
	return &histogram{
		hv:  h.hv,
		lvs: h.lvs.With(labelValues...),
	}
}

// Observe implements Histogram.
func (h *histogram) Observe(value float64) {
	h.hv.With(makeLabels(h.lvs...)).Observe(value)
}

func makeLabels(labelValues ...string) prometheus.Labels {
	labels := prometheus.Labels{}
	for i := 0; i < len(labelValues); i += 2 {
		labels[labelValues[i]] = labelValues[i+1]
	}
	return labels
}
