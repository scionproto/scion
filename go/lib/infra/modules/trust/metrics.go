// Copyright 2018 Anapaya Systems
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

package trust

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

const (
	subsystem = "trust"
)

var (
	TRCRequests   prometheus.Counter
	ChainRequests prometheus.Counter
)

// InitMetrics initializes the metrics for trust request handlers.
func InitMetrics(namespace, elem string) {
	constLabels := prometheus.Labels{"elem": elem}
	newC := func(name, help string) prometheus.Counter {
		return prom.NewCounter(namespace, "", name, help, constLabels)
	}
	TRCRequests = newC("trc_requests_total", "Number of TRC requests received.")
	ChainRequests = newC("chain_requests_total", "Number of Chain requests received.")
}

// IncCntr increments cntr if it is non-nil.
func IncCntr(cntr prometheus.Counter) {
	if cntr != nil {
		cntr.Inc()
	}
}
