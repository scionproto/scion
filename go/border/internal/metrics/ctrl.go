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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

// Control type values
const (
	//
	IFStateInfo = "ifstate_info"
	IFStateReq  = "ifstate_request"
	Revocation  = "revocation"
)

type ControlLabels struct {
	Result string
	Type   string
	Src    string
	Dst    string
}

func (l *ControlLabels) Labels() []string {
	return []string{"result", "type", "src", "dst"}
}

func (l *ControlLabels) Values() []string {
	return []string{l.Result, l.Type, l.Src, l.Dst}
}

type control struct {
	pkts    *prometheus.CounterVec
	ifstate *prometheus.GaugeVec
}

func newControl() control {
	sub := "control"
	intf := IntfLabels{}
	l := intf.Labels()
	return control{
		pkts: prom.NewCounterVec(Namespace, sub,
			"pkts_total", "Total number of processed packets.", l),
		ifstate: prom.NewGaugeVec(Namespace, sub,
			"interface_active", "Interface is active.", l),
	}
}

func (c *control) PktsWith(l ControlLabels) prometheus.Counter {
	return c.pkts.WithLabelValues(l.Values()...)
}

func (c *control) IFStateWith(l IntfLabels) prometheus.Gauge {
	return c.ifstate.WithLabelValues(l.Values()...)
}
