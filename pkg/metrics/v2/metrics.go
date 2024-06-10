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

// Package metrics contains interfaces for generic metrics primitives, to
// facilitate mocking metrics in unit tests.
//
// Most packages will want to use the types in this package, leaving the choice
// of metric implementation (e.g., Prometheus) to the application main function.
//
// The types closely follow the Prometheus Go client library interfaces, for
// easy plugging of Prometheus metrics.
package metrics

import (
	"time"
)

// Counter describes a metric that accumulates values monotonically.
// An example of a counter is the number of received HTTP requests.
type Counter interface {
	Add(delta float64)
}

// Gauge describes a metric that takes specific values over time.
// An example of a gauge is the current depth of a job queue.
type Gauge interface {
	Set(value float64)
	Add(delta float64)
}

// Histogram describes a metric that takes repeated observations of the same
// kind of thing, and produces a statistical summary of those observations,
// typically expressed as quantiles or buckets. An example of a histogram is
// HTTP request latencies.
type Histogram interface {
	Observe(value float64)
}

// CounterAdd increases the passed in counter by the amount specified.
// This is a no-op if c is nil.
func CounterAdd(c Counter, delta float64) {
	if c != nil {
		c.Add(delta)
	}
}

// CounterInc increases the passed in counter by 1.
// This is a no-op if c is nil.
func CounterInc(c Counter) {
	CounterAdd(c, 1)
}

// GaugeSet sets the passed in gauge to the value specified.
// This is a no-op if g is nil.
func GaugeSet(g Gauge, value float64) {
	if g != nil {
		g.Set(value)
	}
}

// GaugeSetTimestamp sets the passed gauge to the specified time stamp.
// This is a no-op if g is nil.
func GaugeSetTimestamp(g Gauge, ts time.Time) {
	timestamp := func(ts time.Time) float64 {
		if ts.IsZero() {
			return 0
		}
		return float64(ts.UnixNano()) / 1e9
	}
	if g != nil {
		g.Set(timestamp(ts))
	}
}

// GaugeSetCurrentTime sets the passed gauge to the current time.
// This is a no-op if g is nil.
func GaugeSetCurrentTime(g Gauge) {
	GaugeSetTimestamp(g, time.Now())
}

// GaugeAdd increases the passed in gauge by the amount specified.
// This is a no-op if g is nil.
func GaugeAdd(g Gauge, delta float64) {
	if g != nil {
		g.Add(delta)
	}
}

// GaugeInc increases the passed in gauge by 1.
// This is a no-op if g is nil.
func GaugeInc(g Gauge) {
	GaugeAdd(g, 1)
}

// HistogramObserve adds an observation to the histogram.
// This is a no-op if h is nil.
func HistogramObserve(h Histogram, value float64) {
	if h != nil {
		h.Observe(value)
	}
}
