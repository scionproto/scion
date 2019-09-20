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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// IfstateLabels define the labels attached to revocation metrics.
type IfstateLabels struct {
	IfID    common.IFIDType
	NeighAS addr.IA
	State   string
}

// Labels returns the list of labels.
func (l IfstateLabels) Labels() []string {
	return []string{"if_id", "neigh_as", "state"}
}

type exporterI struct {
	Desc *prometheus.Desc
}

func newIfstate() exporterI {
	sub := "ifstate"
	return exporterI{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, sub, "state"),
			"Interface state, 0==inactive/expired/revoked, 1==active",
			IfstateLabels{}.Labels(),
			prometheus.Labels{},
		),
	}
}

// Values returns the label values in the order defined by Labels.
func (l IfstateLabels) Values() []string {
	return []string{l.IfID.String(), l.NeighAS.String(), l.State}
}

// IfstateDesc ...
func IfstateDesc() *prometheus.Desc {
	sub := "ifstate"
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, sub, "state"),
		"Interface state, 0==inactive/expired/revoked, 1==active",
		IfstateLabels{}.Labels(),
		prometheus.Labels{},
	)
}

// IfstateMetric ...
func (e exporterI) IfstateMetric(l IfstateLabels, v float64) prometheus.Metric {
	return prometheus.MustNewConstMetric(e.Desc, prometheus.GaugeValue, v,
		l.Values()...)

}
