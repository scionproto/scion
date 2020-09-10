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

package metrics_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/metrics"
)

func TestTestCounterAdd(t *testing.T) {
	c := metrics.NewTestCounter()

	assert.Equal(t, float64(0), metrics.CounterValue(c))

	c.Add(2)
	assert.Equal(t, float64(2), metrics.CounterValue(c))

	c.Add(4)
	assert.Equal(t, float64(6), metrics.CounterValue(c))
}

func TestTestCounterWith(t *testing.T) {
	t.Run("labeled counters are different series", func(t *testing.T) {
		c := metrics.NewTestCounter()

		lc := c.With("x", "1")

		assert.Equal(t, float64(0), metrics.CounterValue(lc))

		c.Add(2)
		lc.Add(4)

		assert.Equal(t, float64(2), metrics.CounterValue(c))
		assert.Equal(t, float64(4), metrics.CounterValue(lc))
	})
	t.Run("different labels are different series", func(t *testing.T) {
		c := metrics.NewTestCounter()

		a := c.With("x", "1")
		b := c.With("x", "2")

		a.Add(2)
		b.Add(3)

		assert.Equal(t, float64(2), metrics.CounterValue(a))
		assert.Equal(t, float64(3), metrics.CounterValue(b))
	})
	t.Run("different order labels are the same series", func(t *testing.T) {
		c := metrics.NewTestCounter()

		a := c.With("x", "1", "y", "2")
		b := c.With("y", "2", "x", "1")

		a.Add(2)
		b.Add(3)

		assert.Equal(t, float64(5), metrics.CounterValue(a))
		assert.Equal(t, float64(5), metrics.CounterValue(b))
	})
	t.Run("labels can be constructed one at a time", func(t *testing.T) {
		c := metrics.NewTestCounter()

		temporary := c.With("x", "1")
		a := temporary.With("y", "2")
		b := c.With("y", "2", "x", "1")

		a.Add(2)
		b.Add(3)

		assert.Equal(t, float64(5), metrics.CounterValue(a))
		assert.Equal(t, float64(5), metrics.CounterValue(b))
	})
}

func ExampleTestCounter_simple() {
	// This example shows how to write a simple test using a TestCounter.
	type Server struct {
		RequestsHandled metrics.Counter
	}

	Run := func(s *Server) {
		// server logic
		s.RequestsHandled.Add(1)
		s.RequestsHandled.Add(1)
	}

	c := metrics.NewTestCounter()

	s := &Server{
		RequestsHandled: c,
	}
	Run(s)

	// Check metrics
	fmt.Println(metrics.CounterValue(c) == 2)
	// Output:
	// true
}

func ExampleTestCounter_labels() {
	// This example shows how to write a test with labels using a TestCounter.
	type Server struct {
		RequestsHandled metrics.Counter
	}

	Run := func(s *Server) {
		// server logic
		s.RequestsHandled.With("type", "normal").Add(1)
		s.RequestsHandled.With("type", "normal").Add(1)
		s.RequestsHandled.With("type", "authenticated").Add(1)
	}

	c := metrics.NewTestCounter()

	s := &Server{
		RequestsHandled: c,
	}
	Run(s)

	// Check metrics
	fmt.Println(metrics.CounterValue(c.With("type", "normal")) == 2)
	fmt.Println(metrics.CounterValue(c.With("type", "authenticated")) == 1)
	fmt.Println(metrics.CounterValue(c.With("type", "error")) == 0)
	// Output:
	// true
	// true
	// true
}

func TestTestGaugeSet(t *testing.T) {
	g := metrics.NewTestGauge()

	assert.Equal(t, float64(0), metrics.GaugeValue(g))

	g.Set(2)
	assert.Equal(t, float64(2), metrics.GaugeValue(g))

	g.Add(4)
	assert.Equal(t, float64(6), metrics.GaugeValue(g))
}

func TestTestGaugeAdd(t *testing.T) {
	g := metrics.NewTestGauge()

	assert.Equal(t, float64(0), metrics.GaugeValue(g))

	g.Add(2)
	assert.Equal(t, float64(2), metrics.GaugeValue(g))

	g.Add(-4)
	assert.Equal(t, float64(-2), metrics.GaugeValue(g))
}

func TestTestGaugeWith(t *testing.T) {
	t.Run("labeled gauges are different series", func(t *testing.T) {
		g := metrics.NewTestGauge()

		lg := g.With("x", "1")

		assert.Equal(t, float64(0), metrics.GaugeValue(lg))

		g.Set(2)
		lg.Set(4)

		assert.Equal(t, float64(2), metrics.GaugeValue(g))
		assert.Equal(t, float64(4), metrics.GaugeValue(lg))
	})
	t.Run("different labels are different series", func(t *testing.T) {
		g := metrics.NewTestGauge()

		a := g.With("x", "1")
		b := g.With("x", "2")

		a.Set(2)
		b.Set(3)

		assert.Equal(t, float64(2), metrics.GaugeValue(a))
		assert.Equal(t, float64(3), metrics.GaugeValue(b))
	})
	t.Run("different order labels are the same series", func(t *testing.T) {
		g := metrics.NewTestGauge()

		a := g.With("x", "1", "y", "2")
		b := g.With("y", "2", "x", "1")

		a.Set(2)
		b.Set(3)

		assert.Equal(t, float64(3), metrics.GaugeValue(a))
		assert.Equal(t, float64(3), metrics.GaugeValue(b))
	})
	t.Run("labels can be constructed one at a time", func(t *testing.T) {
		g := metrics.NewTestGauge()

		temporary := g.With("x", "1")
		a := temporary.With("y", "2")
		b := g.With("y", "2", "x", "1")

		a.Set(2)
		b.Set(3)

		assert.Equal(t, float64(3), metrics.GaugeValue(a))
		assert.Equal(t, float64(3), metrics.GaugeValue(b))
	})
}

func ExampleTestGauge_simple() {
	// This example shows how to write a simple test using a TestGauge.
	type Server struct {
		RequestsHandled metrics.Gauge
	}

	Run := func(s *Server) {
		// server logic
		s.RequestsHandled.Set(6)
	}

	g := metrics.NewTestGauge()

	s := &Server{
		RequestsHandled: g,
	}
	Run(s)

	// Check metrics
	fmt.Println(metrics.GaugeValue(g) == 6)
	// Output:
	// true
}

func ExampleTestGauge_labels() {
	// This example shows how to write a test with labels using a TestGauge.
	type Server struct {
		RunningWorkers metrics.Gauge
	}

	Run := func(s *Server) {
		// server logic
		s.RunningWorkers.With("type", "http").Set(8)
		s.RunningWorkers.With("type", "https").Set(5)
	}

	g := metrics.NewTestGauge()

	s := &Server{
		RunningWorkers: g,
	}
	Run(s)

	// Check metrics
	fmt.Println(metrics.GaugeValue(g.With("type", "http")) == 8)
	fmt.Println(metrics.GaugeValue(g.With("type", "https")) == 5)
	fmt.Println(metrics.GaugeValue(g.With("type", "other")) == 0)
	// Output:
	// true
	// true
	// true
}
