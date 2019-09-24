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

// Namespace is the metrics namespace for the infra topology module.
const Namespace = "itopo"

// Topology types.
const (
	Static  = "static"
	Dynamic = "dynamic"
)

// Result labels.
const (
	Success     = prom.Success
	OkIgnored   = "ok_ignored"
	ErrValidate = "err_validate"
	ErrCommit   = "err_commit"
)

// Metrics initialization.
var (
	Current = newCurrent()
	Updates = newUpdates()
)

// CurrentLabels defines the current topology label set.
type CurrentLabels struct {
	Type string
}

// Labels returns the name of the labels in correct order.
func (l CurrentLabels) Labels() []string {
	return []string{"type"}
}

// Values returns the values of the label in correct order.
func (l CurrentLabels) Values() []string {
	return []string{l.Type}
}

type current struct {
	timestamp *prometheus.GaugeVec
	ttl       *prometheus.GaugeVec
	active    *prometheus.GaugeVec
}

func newCurrent() current {
	return current{
		timestamp: prom.NewGaugeVec(Namespace, "", "current_timestamp",
			"The timestamp of the current topology. Remains set, even when inactive.",
			CurrentLabels{}.Labels()),
		ttl: prom.NewGaugeVec(Namespace, "", "current_ttl_seconds",
			"The TTL of the current topology. 0 indicates no TTL. Remains set, even when inactive.",
			CurrentLabels{}.Labels()),
		active: prom.NewGaugeVec(Namespace, "", "current_active",
			"Indicate whether the current topology is active. 0=inactive, 1=active.",
			CurrentLabels{}.Labels()),
	}
}

func (c current) Timestamp(l CurrentLabels) prometheus.Gauge {
	return c.timestamp.WithLabelValues(l.Values()...)
}

func (c current) TTL(l CurrentLabels) prometheus.Gauge {
	return c.ttl.WithLabelValues(l.Values()...)
}

func (c current) Active(l CurrentLabels) prometheus.Gauge {
	return c.active.WithLabelValues(l.Values()...)
}

// UpdateLabels defines the update label set.
type UpdateLabels struct {
	Type   string
	Result string
}

// Labels returns the name of the labels in correct order.
func (l UpdateLabels) Labels() []string {
	return []string{"type", prom.LabelResult}
}

// Values returns the values of the label in correct order.
func (l UpdateLabels) Values() []string {
	return []string{l.Type, l.Result}
}

// WithResult returns the label set with the modified result.
func (l UpdateLabels) WithResult(result string) UpdateLabels {
	l.Result = result
	return l
}

type updates struct {
	last  *prometheus.GaugeVec
	total *prometheus.CounterVec
}

func newUpdates() updates {
	return updates{
		last: prom.NewGaugeVec(Namespace, "", "last_updates",
			"Timestamp of the last update attempts.", UpdateLabels{}.Labels()),
		total: prom.NewCounterVec(Namespace, "", "updates_total",
			"The total number of updates.", UpdateLabels{}.Labels()),
	}
}

func (u updates) Last(l UpdateLabels) prometheus.Gauge {
	return u.last.WithLabelValues(l.Values()...)
}

func (u updates) Total(l UpdateLabels) prometheus.Counter {
	return u.total.WithLabelValues(l.Values()...)
}
