// Copyright 2026 ETH Zurich
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

package hbird

import (
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/private/topology"
)

type Metrics struct {
	TopoLoader topology.LoaderMetrics
}

func NewMetrics() *Metrics {
	return &Metrics{
		TopoLoader: loaderMetrics(),
	}
}

func loaderMetrics() topology.LoaderMetrics {
	u := prom.NewCounterVec("", "",
		"topology_updates_total",
		"The total number of updates.",
		[]string{prom.LabelResult},
	)
	return topology.LoaderMetrics{
		ValidationErrors: metrics.NewPromCounter(u).With(prom.LabelResult, "err_validate"),
		ReadErrors:       metrics.NewPromCounter(u).With(prom.LabelResult, "err_read"),
		LastUpdate: metrics.NewPromGauge(
			prom.NewGaugeVec("", "",
				"topology_last_update_time",
				"Timestamp of the last successful update.",
				[]string{},
			),
		),
		Updates: metrics.NewPromCounter(u).With(prom.LabelResult, prom.Success),
	}
}
