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
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

var _ prometheus.Collector = (*Collector)(nil)

// Collector implements a prometheus collector that exports the state of
// all interfaces.
type Collector struct {
	desc  *prometheus.Desc
	intfs *Interfaces
}

// NewCollector creates a prometheus collector that exports the state of all
// interfaces.
func NewCollector(intfs *Interfaces, subsystemName string) *Collector {
	return &Collector{
		desc: prometheus.NewDesc(
			prometheus.BuildFQName("beacon_srv", subsystemName, "ifstate"),
			"Interface state, 0 means down, 1 up. More details in labels (ifid, state)",
			[]string{"ifid", "state"},
			prometheus.Labels{},
		),
		intfs: intfs,
	}
}

func (c *Collector) Collect(mc chan<- prometheus.Metric) {
	for ifid, intf := range c.intfs.All() {
		state := intf.State()
		var up float64
		if state == Active {
			up = 1
		}
		mc <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, up,
			strconv.FormatUint(uint64(ifid), 10), string(state))
	}
}

func (c *Collector) Describe(dc chan<- *prometheus.Desc) {
	dc <- c.desc
}
