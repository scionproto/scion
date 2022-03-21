// Copyright 2020 Anapaya Systems
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
	IFStateInfo = "ifstate_info"
	IFStateReq  = "ifstate_request"
	Revocation  = "revocation"
)

type ControlLabels struct {
	// Result is the outcome of processing the packet.
	Result string
}

// Labels returns the list of labels.
func (l ControlLabels) Labels() []string {
	return []string{"result"}
}

// Values returns the label values in the order defined by Labels.
func (l ControlLabels) Values() []string {
	return []string{l.Result}
}

type SentRevInfoLabels struct {
	// Result is the outcome of processing the packet.
	Result string
	// SVC is the destination svc address.
	SVC string
}

// Labels returns the list of labels.
func (l SentRevInfoLabels) Labels() []string {
	return []string{"result", "svc"}
}

// Values returns the label values in the order defined by Labels.
func (l SentRevInfoLabels) Values() []string {
	return []string{l.Result, l.SVC}
}

type control struct {
	reads               *prometheus.CounterVec
	processErrors       *prometheus.CounterVec
	receivedIFStateInfo *prometheus.CounterVec
	sentIFStateReq      *prometheus.CounterVec
	ifstate             *prometheus.GaugeVec
	ifstateTick         prometheus.Counter
	readRevInfos        *prometheus.CounterVec
	sentRevInfos        *prometheus.CounterVec
}

func newControl() control {
	sub := "ctrl"
	return control{
		reads: prom.NewCounterVecWithLabels(Namespace, sub,
			"reads_total", "Total number of read messages.", ControlLabels{}),
		processErrors: prom.NewCounterVecWithLabels(Namespace, sub,
			"process_errors", "Total number of process errors.", ControlLabels{}),
		receivedIFStateInfo: prom.NewCounterVecWithLabels(Namespace, sub,
			"received_ifstateinfo_total", "Total number of recevied ifstate infos.",
			ControlLabels{}),
		sentIFStateReq: prom.NewCounterVecWithLabels(Namespace, sub,
			"sent_ifstatereq_total", "Total number of sent ifstate requests.",
			ControlLabels{}),
		ifstate: prom.NewGaugeVecWithLabels(Namespace, sub,
			"interface_active", "Interface is active.", IntfLabels{}),
		ifstateTick: prom.NewCounter(Namespace, sub,
			"ifstate_ticks_total", "Total number of IFState requests ticks."),
		readRevInfos: prom.NewCounterVecWithLabels(Namespace, sub,
			"read_revinfos_total", "Total number of read revinfos.", ControlLabels{}),
		sentRevInfos: prom.NewCounterVecWithLabels(Namespace, sub,
			"sent_revinfos_total", "Total number of sent revinfos.", SentRevInfoLabels{}),
	}
}

// Reads returns the counter for the given label set.
func (c *control) Reads(l ControlLabels) prometheus.Counter {
	return c.reads.WithLabelValues(l.Values()...)
}

// ProcessErrors returns the counter for the given label set.
func (c *control) ProcessErrors(l ControlLabels) prometheus.Counter {
	return c.processErrors.WithLabelValues(l.Values()...)
}

func (c *control) ProcessErrorsVec() *prometheus.CounterVec {
	return c.processErrors
}

// ReceivedIFStateInfo returns the counter for the given label set.
func (c *control) ReceivedIFStateInfo(l ControlLabels) prometheus.Counter {
	return c.receivedIFStateInfo.WithLabelValues(l.Values()...)
}

func (c *control) ReceivedIFStateInfoVec() *prometheus.CounterVec {
	return c.receivedIFStateInfo
}

// SentIFStateReq returns the counter for the given label set.
func (c *control) SentIFStateReq(l ControlLabels) prometheus.Counter {
	return c.sentIFStateReq.WithLabelValues(l.Values()...)
}

func (c *control) SendIFStateReqVec() *prometheus.CounterVec {
	return c.sentIFStateReq
}

// IFState returns the gauge for the given label set.
func (c *control) IFState(l IntfLabels) prometheus.Gauge {
	return c.ifstate.WithLabelValues(l.Values()...)
}

// IFStateTick returns the counter for the given label set.
func (c *control) IFStateTick() prometheus.Counter {
	return c.ifstateTick
}

// ReadRevInfos returns the counter for the given label set.
func (c *control) ReadRevInfos(l ControlLabels) prometheus.Counter {
	return c.readRevInfos.WithLabelValues(l.Values()...)
}

// SentRevInfos returns the counter for the given label set.
func (c *control) SentRevInfos(l SentRevInfoLabels) prometheus.Counter {
	return c.sentRevInfos.WithLabelValues(l.Values()...)
}

func (c *control) SentRevInfosVec() *prometheus.CounterVec {
	return c.sentRevInfos
}
