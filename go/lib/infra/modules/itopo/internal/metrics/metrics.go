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
	"math"
	"time"

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

var (
	// Current is the single-instance struct to get prometheus gauges.
	Current = newCurrent()
	// Updates is the single-instance struct to get prometheus counters and gauges.
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
	active    prometheus.Gauge
}

func newCurrent() current {
	return current{
		timestamp: prom.NewGaugeVecWithLabels(Namespace, "", "creation_time_seconds",
			"The creation time specified in the current topology."+
				"Remains set for dynamic topology, even when inactive.", CurrentLabels{}),
		active: prom.NewGauge(Namespace, "", "dynamic_active",
			"Indicate whether the dynamic topology is set and active. 0=inactive, 1=active."),
	}
}

// Timestamp returns the prometheus gauge.
func (c current) Timestamp(l CurrentLabels) prometheus.Gauge {
	return c.timestamp.WithLabelValues(l.Values()...)
}

// Active returns the prometheus gauge.
func (c current) Active() prometheus.Gauge {
	return c.active
}

// UpdateLabels defines the update label set.
type UpdateLabels struct {
	Type, Result string
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
		last: prom.NewGaugeVecWithLabels(Namespace, "", "last_updates",
			"Timestamp of the last update attempts.", UpdateLabels{}),
		total: prom.NewCounterVecWithLabels(Namespace, "", "updates_total",
			"The total number of updates.", UpdateLabels{}),
	}
}

// Last returns the prometheus gauge.
func (u updates) Last(l UpdateLabels) prometheus.Gauge {
	return u.last.WithLabelValues(l.Values()...)
}

// Total returns the prometheus counter.
func (u updates) Total(l UpdateLabels) prometheus.Counter {
	return u.total.WithLabelValues(l.Values()...)
}

// Timestamp returns the time as unix time in seconds.
func Timestamp(ts time.Time) float64 {
	if ts.IsZero() {
		return 0
	}
	return float64(ts.UnixNano() / 1e9)
}

// Expiry returns the expiry time as unix time in seconds. In case of the zero
// value, +inf is returned.
func Expiry(ts time.Time) float64 {
	if ts.IsZero() {
		return math.Inf(+1)
	}
	return float64(ts.UnixNano() / 1e9)
}
