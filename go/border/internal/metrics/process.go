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

const (
	// Drop is the output interface for packets with errors that are dropped.
	Drop = "drop"
	// Ctrl is the output interface for packets sent to control.
	Ctrl = "control"
)

type ProcessLabels struct {
	// Result is the outcome of processing the packet.
	Result string
	// In is the input SCION interface.
	In string
	// Out is the output SCION interface.
	Out string
}

// Labels returns the list of labels.
func (l ProcessLabels) Labels() []string {
	return []string{"result", "intf_in", "intf_out"}
}

// Values returns the label values in the order defined by Labels.
func (l ProcessLabels) Values() []string {
	return []string{l.Result, l.In, l.Out}
}

type process struct {
	pkts *prometheus.CounterVec
	time *prometheus.CounterVec
}

func newProcess() process {
	sub := "process"
	return process{
		pkts: prom.NewCounterVec(Namespace, sub,
			"pkts_total", "Total number of processed packets.", ProcessLabels{}.Labels()),
		time: prom.NewCounterVec(Namespace, sub,
			"time_seconds_total", "Total packet processing time.", IntfLabels{}.Labels()),
	}
}

// PktsWith returns the counter for the given label set.
func (p *process) PktsWith(l ProcessLabels) prometheus.Counter {
	return p.pkts.WithLabelValues(l.Values()...)
}

// TimeWith returns the counter for the given label set.
func (p *process) TimeWith(l IntfLabels) prometheus.Counter {
	return p.time.WithLabelValues(l.Values()...)
}
