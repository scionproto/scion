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

	"github.com/scionproto/scion/pkg/metrics/v2"
)

func TestTestCounterAdd(t *testing.T) {
	c := metrics.NewTestCounter()

	assert.Equal(t, float64(0), metrics.CounterValue(c))

	c.Add(2)
	assert.Equal(t, float64(2), metrics.CounterValue(c))

	c.Add(4)
	assert.Equal(t, float64(6), metrics.CounterValue(c))
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
		RequestsHandledNormal metrics.Counter
		RequestsHandledError  metrics.Counter
		RequestsHandledAuth   metrics.Counter
	}

	Run := func(s *Server) {
		// server logic
		s.RequestsHandledNormal.Add(1)
		s.RequestsHandledNormal.Add(1)
		s.RequestsHandledAuth.Add(1)
	}

	s := &Server{
		RequestsHandledNormal: metrics.NewTestCounter(),
		RequestsHandledError:  metrics.NewTestCounter(),
		RequestsHandledAuth:   metrics.NewTestCounter(),
	}
	Run(s)

	// Check metrics
	fmt.Println(metrics.CounterValue(s.RequestsHandledNormal) == 2)
	fmt.Println(metrics.CounterValue(s.RequestsHandledAuth) == 1)
	fmt.Println(metrics.CounterValue(s.RequestsHandledError) == 0)
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
	// For actual metrics initialization, labels would be fixed on construction.
	var (
		httpGauge  = metrics.NewTestGauge()
		httpsGauge = metrics.NewTestGauge()
		otherGauge = metrics.NewTestGauge()
	)
	// This example shows how to write a test with labels using a TestGauge.
	type Server struct {
		RunningWorkers func(typ string) metrics.Gauge
	}

	Run := func(s *Server) {
		// server logic
		s.RunningWorkers("http").Set(8)
		s.RunningWorkers("https").Set(5)
	}

	s := &Server{
		RunningWorkers: func(typ string) metrics.Gauge {
			switch typ {
			case "http":
				return httpGauge
			case "https":
				return httpsGauge
			default:
				return otherGauge
			}
		},
	}
	Run(s)

	// Check metrics
	fmt.Println(metrics.GaugeValue(httpGauge) == 8)
	fmt.Println(metrics.GaugeValue(httpsGauge) == 5)
	fmt.Println(metrics.GaugeValue(otherGauge) == 0)
	// Output:
	// true
	// true
	// true
}
