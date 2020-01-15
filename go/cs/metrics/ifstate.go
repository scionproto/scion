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
	"github.com/scionproto/scion/go/lib/prom"
)

type ifstate struct {
	Desc                  *prometheus.Desc
	issued, duration, out prometheus.CounterVec
}

func newIfstate() ifstate {
	sub := "ifstate"
	return ifstate{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(BSNamespace, sub, "state"),
			"Interface state, 0==inactive/expired/revoked, 1==active",
			IfstateLabels{}.Labels(),
			prometheus.Labels{},
		),
		issued: *prom.NewCounterVecWithLabels(BSNamespace, sub,
			"issued_revocations_total",
			"Total number of issued revocations.", IssuedLabels{}),
		duration: *prom.NewCounterVecWithLabels(BSNamespace, sub,
			"revocations_duration_seconds_total",
			"Duration in seconds of issued revocations.", DurationLabels{}),
		out: *prom.NewCounterVecWithLabels(BSNamespace, sub,
			"sent_revocations_total",
			"Total number of sent revocations.", SentLabels{}),
	}
}

// IfstateMetric returns a prometheus metric
func (e ifstate) IfstateMetric(l IfstateLabels, v float64) prometheus.Metric {
	return prometheus.MustNewConstMetric(e.Desc, prometheus.GaugeValue, v,
		l.Values()...)
}

// Issued return the issued counter
func (e *ifstate) Issued(l IssuedLabels) prometheus.Counter {
	return e.issued.WithLabelValues(l.Values()...)
}

// Duration return the duration counter
func (e *ifstate) Duration(l DurationLabels) prometheus.Counter {
	return e.duration.WithLabelValues(l.Values()...)
}

// Sent return the duration counter
func (e *ifstate) Sent(l SentLabels) prometheus.Counter {
	return e.out.WithLabelValues(l.Values()...)
}

// SentLabels define the labels attached to sent revocation counter.
type SentLabels struct {
	Dst string
}

// Labels returns the list of labels.
func (l SentLabels) Labels() []string {
	return []string{"dst"}
}

// Values returns the label values in the order defined by Labels.
func (l SentLabels) Values() []string {
	return []string{l.Dst}
}

// IfstateLabels define the labels attached to interface state.
type IfstateLabels struct {
	IfID    common.IFIDType
	NeighIA addr.IA
}

// Labels returns the list of labels.
func (l IfstateLabels) Labels() []string {
	return []string{"if_id", prom.LabelNeighIA}
}

// Values returns the label values in the order defined by Labels.
func (l IfstateLabels) Values() []string {
	return []string{l.IfID.String(), l.NeighIA.String()}
}

// IssuedLabels define the labels attached to revocation metrics.
type IssuedLabels struct {
	IfID    common.IFIDType
	NeighIA addr.IA
	State   string
}

// Labels returns the list of labels.
func (l IssuedLabels) Labels() []string {
	return []string{"if_id", prom.LabelNeighIA, "state"}
}

// Values returns the label values in the order defined by Labels.
func (l IssuedLabels) Values() []string {
	return []string{l.IfID.String(), l.NeighIA.String(), l.State}
}

// DurationLabels define the labels attached to duration metric.
type DurationLabels struct {
	IfID    common.IFIDType
	NeighIA addr.IA
}

// Labels returns the list of labels.
func (l DurationLabels) Labels() []string {
	return []string{"if_id", prom.LabelNeighIA}
}

// Values returns the label values in the order defined by Labels.
func (l DurationLabels) Values() []string {
	return []string{l.IfID.String(), l.NeighIA.String()}
}
