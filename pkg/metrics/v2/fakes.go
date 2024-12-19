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
	"sync"
)

// node represents the shared implementation of gauges and counters.
type node struct {
	mtx sync.Mutex
	v   float64
}

func (b *node) add(delta float64, canBeNegative bool) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	if !canBeNegative && delta < 0 {
		panic("counter increment value is < 0")
	}
	b.v += delta
}

func (b *node) set(v float64) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.v = v
}

func (b *node) value() float64 {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.v
}

// TestCounter implements a counter for use in tests.
type TestCounter struct {
	*node
}

// NewTestCounter creates a new counter for use in tests. See the examples for more information on
// how to use this.
func NewTestCounter() *TestCounter {
	return &TestCounter{node: &node{}}
}

// Add increases the internal value of the counter by the specified delta. Value can be negative.
func (c *TestCounter) Add(delta float64) {
	c.add(delta, false)
}

// CounterValue extracts the value out of a TestCounter. If the argument is not a *TestCounter,
// CounterValue will panic.
func CounterValue(c Counter) float64 {
	return c.(*TestCounter).value()
}

// TestGauge implements a gauge for use in tests.
type TestGauge struct {
	*node
}

// NewTestGauge creates a new gauge for use in tests. See the examples for more information on
// how to use this.
func NewTestGauge() *TestGauge {
	return &TestGauge{node: &node{}}
}

// Set sets the internal value of the gauge to the specified value.
func (g *TestGauge) Set(v float64) {
	g.set(v)
}

// Add increases the internal value of the gauge by the specified delta. The delta must be positive.
func (g *TestGauge) Add(delta float64) {
	g.add(delta, true)
}

// GaugeValue extracts the value out of a TestGauge. If the argument is not a *TestGauge,
// GaugeValue will panic.
func GaugeValue(g Gauge) float64 {
	return g.(*TestGauge).value()
}
