// Copyright 2019 Anapaya Systems
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

package ifstate

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/cs/metrics"
)

var _ prometheus.Collector = (*Collector)(nil)

// Collector implements a prometheus collector that exports the state of  all interfaces.
type Collector struct {
	intfs *Interfaces
}

// NewCollector creates a prometheus collector that exports the state of all interfaces.
func NewCollector(intfs *Interfaces) *Collector {
	return &Collector{
		intfs: intfs,
	}
}

// Collect is called by prometheus to get interface status
func (c *Collector) Collect(mc chan<- prometheus.Metric) {
	for ifid, intf := range c.intfs.All() {
		up := float64(0)
		if intf.State() == Active {
			up = 1
		}
		l := metrics.IfstateLabels{
			IfID:    ifid,
			NeighIA: intf.TopoInfo().IA,
		}
		mc <- metrics.Ifstate.IfstateMetric(l, up)
	}
}

// Describe is called by prometheus to get description
func (c *Collector) Describe(dc chan<- *prometheus.Desc) {
	dc <- metrics.Ifstate.Desc
}
