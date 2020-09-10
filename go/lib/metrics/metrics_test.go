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
	"github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/metrics"
)

func ExampleCounter_interface() {
	// LITERALINCLUDE ExampleCounter_Interface START
	type Giant struct {
		MagicBeansEaten metrics.Counter
	}

	type BeanLabels struct {
		Color string // can be "blue" or "orange"
	}

	// Use a func for this to be displayed properly in the godoc, but this should be a method.
	Expand := func(labels BeanLabels) []string {
		// converts labels to a slice of strings
		return []string{"color", labels.Color}
	}

	giant := Giant{}
	labels := BeanLabels{Color: "orange"}
	counter := giant.MagicBeansEaten.With(Expand(labels)...)
	counter.Add(4)
	// LITERALINCLUDE ExampleCounter_Interface END
}

func ExampleCounter_implementation() {
	// LITERALINCLUDE ExampleCounter_Implementation START
	type Giant struct {
		MagicBeansEaten metrics.Counter
	}

	counter := prometheus.NewCounterFrom(stdprometheus.CounterOpts{
		Name: "magic_beans_eaten_total",
		Help: "Number of magic beans eaten.",
	}, nil)

	giant := Giant{
		MagicBeansEaten: counter,
	}
	giant.MagicBeansEaten.Add(4)
	// LITERALINCLUDE ExampleCounter_Implementation END
}
