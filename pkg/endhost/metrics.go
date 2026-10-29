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

package endhost

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
)

type RequestMetric struct {
	Requests metrics.Counter
}

func (m RequestMetric) Increment(err error, extraLabels ...string) {
	result := resultFromErr(err)
	if m.Requests != nil {
		m.Requests.With(append([]string{prom.LabelResult, result}, extraLabels...)...).Add(1)
	}
}

func resultFromErr(err error) string {
	if err == nil {
		return prom.Success
	}
	if serrors.IsTimeout(err) {
		return prom.ErrTimeout
	}
	return prom.ErrNotClassified
}

var metricListUnderlaysTotal = newRequestMetric("list_underlays", "List underlays requests", []string{prom.LabelResult})
var metricListSegmentsTotal = newRequestMetric("list_segments", "List segments", []string{prom.LabelResult, prom.LabelDst})
var metricListChainsTotal = newRequestMetric("list_chains", "List chains", []string{prom.LabelResult})
var metricGetTRCTotal = newRequestMetric("get_trc", "Get TRC", []string{prom.LabelResult})
var metricASHostKeyTotal = newRequestMetric("as_host_key", "AS-Host key", []string{prom.LabelResult})
var metricHostASKeyTotal = newRequestMetric("host_as_key", "Host-AS key", []string{prom.LabelResult})
var metricHostHostKeyTotal = newRequestMetric("host_host_key", "Host-Host key", []string{prom.LabelResult})

func newRequestMetric(subsystem string, description string, labels []string) RequestMetric {
	return RequestMetric{
		Requests: metrics.NewPromCounterFrom(
			prometheus.CounterOpts{
				Namespace: "endhost_api",
				Subsystem: subsystem,
				Name:      "requests_total",
				Help:      fmt.Sprintf("The amount of %s requests.", description),
			}, labels,
		),
	}
}
