// Copyright 2019 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/prom"
)

// Namespace is the metrics namespace for the metrics in this package.
const Namespace = "lib"

const sub = "reconnect"

var (
	// M exposes all the initialized metrics for this package.
	M = newMetrics()
)

type metrics struct {
	timeouts prometheus.Counter
	retries  prometheus.Counter
}

func newMetrics() metrics {
	return metrics{
		timeouts: prom.NewCounter(Namespace, sub, "timeouts_total",
			"Total number of reconnection attempt timeouts"),
		retries: prom.NewCounter(Namespace, sub, "retries_total",
			"Total number of reconnection attempt retries"),
	}
}

// Timeouts returns a counter for timeout errors.
func (m metrics) Timeouts() prometheus.Counter {
	return m.timeouts
}

// Retries returns a counter for individual reconnection attempts.
func (m metrics) Retries() prometheus.Counter {
	return m.retries
}
