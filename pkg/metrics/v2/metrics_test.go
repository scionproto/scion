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
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/metrics/v2"
)

func ExampleCounter_implementation() {
	// LITERALINCLUDE ExampleCounter_Implementation START
	type Giant struct {
		MagicBeansEaten metrics.Counter
		RedPillsEaten   metrics.Counter
		BluePillsEaten  metrics.Counter
	}

	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "magic_beans_eaten_total",
		Help: "Number of magic beans eaten.",
	})
	pillCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pills_eaten_total",
		Help: "Number of pills eaten.",
	}, []string{"color"})

	giant := Giant{
		MagicBeansEaten: counter,
		RedPillsEaten:   pillCounter.WithLabelValues("red"),
		BluePillsEaten: pillCounter.With(prometheus.Labels{
			"color": "blue",
		}),
	}
	giant.MagicBeansEaten.Add(4)
	giant.RedPillsEaten.Add(2)
	giant.BluePillsEaten.Add(1)
	// LITERALINCLUDE ExampleCounter_Implementation END
}
