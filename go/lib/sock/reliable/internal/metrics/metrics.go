// Copyright 2019 ETH Zurich
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

// Namespace is the metrics namespace for the metrics in this package.
const Namespace = "lib"

const sub = "reliable"

var (
	// M exposes all the initialized metrics for this package.
	M = newMetrics()
)

// DialLabels contains the labels for Dial calls.
type DialLabels struct {
	Result string
}

// Labels returns the list of labels.
func (l DialLabels) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l DialLabels) Values() []string {
	return []string{l.Result}
}

// RegisterLabels contains the labels for Register calls.
type RegisterLabels struct {
	Result string
	SVC    string
}

// Labels returns the list of labels.
func (l RegisterLabels) Labels() []string {
	return []string{prom.LabelResult, "svc"}
}

// Values returns the label values in the order defined by Labels.
func (l RegisterLabels) Values() []string {
	return []string{l.Result, l.SVC}
}

// IOLabels contains the labels for Read and Write calls.
type IOLabels struct {
	Result string
}

// Labels returns the list of labels.
func (l IOLabels) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l IOLabels) Values() []string {
	return []string{l.Result}
}

type metrics struct {
	dials     *prometheus.CounterVec
	registers *prometheus.CounterVec
	reads     *prometheus.HistogramVec
	writes    *prometheus.HistogramVec
}

func newMetrics() metrics {
	return metrics{
		dials: prom.NewCounterVecWithLabels(Namespace, sub, "dials_total",
			"Total number of Dial calls.", DialLabels{}),
		registers: prom.NewCounterVecWithLabels(Namespace, sub, "registers_total",
			"Total number of Register calls.", RegisterLabels{}),
		reads: prom.NewHistogramVecWithLabels(Namespace, sub, "reads_total",
			"Total number of Read calls", IOLabels{}, prom.DefaultSizeBuckets),
		writes: prom.NewHistogramVecWithLabels(Namespace, sub, "writes_total",
			"Total number of Write calls", IOLabels{}, prom.DefaultSizeBuckets),
	}
}

func (m metrics) Dials(l DialLabels) prometheus.Counter {
	return m.dials.WithLabelValues(l.Values()...)
}

func (m metrics) Registers(l RegisterLabels) prometheus.Counter {
	return m.registers.WithLabelValues(l.Values()...)
}

func (m metrics) Reads(l IOLabels) prometheus.Observer {
	return m.reads.WithLabelValues(l.Values()...)
}

func (m metrics) Writes(l IOLabels) prometheus.Observer {
	return m.writes.WithLabelValues(l.Values()...)
}
