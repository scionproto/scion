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
	"fmt"
	"sort"
	"strings"
	"sync"
)

// node represents the shared implementation of gauges and counters. The label namespace of each
// new counter or gauge is modeled by a hierarchy of nodes that is organized as a tree with two
// levels.
type node struct {
	mtx sync.Mutex

	// root points to the manually created node from which this node was created. Root nodes will
	// point to themselves, while children created by calling With will point to the root of their
	// hierarchy.
	root *node
	// children maps canonicalized label values to child nodes. Only root (that is,
	// manually created by the caller) node objects initialize this field. This maintains all
	// child nodes that can be traced back to the same root node.
	children map[string]*node

	// labels maintains the label context (key, value pairs) for this entry. The root node
	// starts with an empty label set, but child nodes will always have label data. Children
	// of the children will inherit and add to the label sets.
	labels map[string]string
	v      float64
}

func (b *node) with(labels ...string) *node {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	if len(labels)%2 != 0 {
		panic("number of labels is odd")
	}
	if b.children == nil {
		b.children = make(map[string]*node)
	}
	if b.root == nil {
		b.root = b
	}

	labelsMap := createLabelsMap(b.labels, labels)
	return b.findCounter(labelsMap)
}

func createLabelsMap(existingLabels map[string]string, newLabels []string) map[string]string {
	labelsMap := make(map[string]string)
	for k, v := range existingLabels {
		labelsMap[k] = v
	}
	for i := 0; i < len(newLabels)/2; i++ {
		k, v := newLabels[2*i], newLabels[2*i+1]
		if _, ok := labelsMap[k]; ok {
			panic(fmt.Sprintf("duplicate label key: %s", k))
		}
		labelsMap[k] = v
	}
	return labelsMap
}

// findCounter returns an existing counter if it matches the labels, or creates a new one if one is
// not found.
func (b *node) findCounter(labelsMap map[string]string) *node {
	// To ensure that reading and writing label data on the registry maintained by the root
	// counter is safe for concurrent use, we acquire the lock if we're not root.
	if b.root != b {
		b.root.mtx.Lock()
		defer b.root.mtx.Unlock()
	}

	canonicalLabels := canonicalize(labelsMap)
	counter, ok := b.root.children[canonicalLabels]
	if ok {
		return counter
	}
	b.root.children[canonicalLabels] = &node{
		labels: labelsMap,
		root:   b.root,
	}
	return b.root.children[canonicalLabels]
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

// canonicalize returns a canonical description of label keys and values.
//
// The format is obtained by sorting the label keys, joining them with their value, and then
// joining all the pairs together. For example, if label key "x" has value "1", and label key "y"
// has value "2", the canonical representation is "x=1.y=2". The canonical format is used by a
// root label namespace (e.g., TestCounter) to manage unique time-series.
func canonicalize(m map[string]string) string {
	// This function is horribly inefficient, but it's only used for testing so we don't care.
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var keyValues []string
	for _, k := range keys {
		keyValues = append(keyValues, k+"="+m[k])
	}

	return strings.Join(keyValues, ".")
}

// TestCounter implements a counter for use in tests.
//
// Each newly created TestCounter is a stand-alone label namespace. That means time-series behave
// as expected, e.g., creating two counters with the same labels by calling With will yield counters
// that represent the same time-series. The examples illustrate how this can be used to write a
// simple test.
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

// With creates a new counter that includes the specified labels in addition to any labels the
// parent counter might have.
func (c *TestCounter) With(labels ...string) Counter {
	return &TestCounter{
		node: c.with(labels...),
	}
}

// CounterValue extracts the value out of a TestCounter. If the argument is not a *TestCounter,
// CounterValue will panic.
func CounterValue(c Counter) float64 {
	return c.(*TestCounter).value()
}

// TestGauge implements a gauge for use in tests.
//
// Each newly created TestGauge is a stand-alone label namespace. That means time-series behave
// as expected, e.g., creating two gauges with the same labels by calling With will yield gauges
// that represent the same time-series. The examples illustrate how this can be used to write a
// simple test.
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

// With creates a new gauge that includes the specified labels in addition to any labels the
// parent gauge might have.
func (g *TestGauge) With(labels ...string) Gauge {
	return &TestGauge{
		node: g.with(labels...),
	}
}

// GaugeValue extracts the value out of a TestGauge. If the argument is not a *TestGauge,
// GaugeValue will panic.
func GaugeValue(g Gauge) float64 {
	return g.(*TestGauge).value()
}
