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
	IFStateInfo = "ifstate_info"
	IFStateReq  = "ifstate_request"
	Revocation  = "revocation"
)

type ControlLabels struct {
	// Result is the outcome of processing the packet.
	Result string
	// Type is the type of packet/message.
	Type string
}

// Labels returns the list of labels.
func (l ControlLabels) Labels() []string {
	return []string{"result", "type"}
}

// Values returns the label values in the order defined by Labels.
func (l ControlLabels) Values() []string {
	return []string{l.Result, l.Type}
}

type control struct {
	sentMsgs     *prometheus.CounterVec
	receivedMsgs *prometheus.CounterVec
	ifstate      *prometheus.GaugeVec
	ifstateTick  prometheus.Counter
}

func newControl() control {
	sub := "control"
	return control{
		sentMsgs: prom.NewCounterVec(Namespace, sub,
			"sent_msgs_total", "Total number of sent messages.", ControlLabels{}.Labels()),
		receivedMsgs: prom.NewCounterVec(Namespace, sub,
			"received_msgs_total", "Total number of recevied messages.", ControlLabels{}.Labels()),
		ifstate: prom.NewGaugeVec(Namespace, sub,
			"interface_active", "Interface is active.", IntfLabels{}.Labels()),
		ifstateTick: prom.NewCounter(Namespace, sub,
			"ifstate_ticks_total", "Total number of IFState requests ticks."),
	}
}

// SentMsgs returns the counter for the given label set.
func (c *control) SentMsgs(l ControlLabels) prometheus.Counter {
	return c.sentMsgs.WithLabelValues(l.Values()...)
}

// ReceivedMsgs returns the counter for the given label set.
func (c *control) ReceivedMsgs(l ControlLabels) prometheus.Counter {
	return c.receivedMsgs.WithLabelValues(l.Values()...)
}

// IFState returns the gauge for the given label set.
func (c *control) IFState(l IntfLabels) prometheus.Gauge {
	return c.ifstate.WithLabelValues(l.Values()...)
}

// IFStateTick returns the counter for the given label set.
func (c *control) IFStateTick() prometheus.Counter {
	return c.ifstateTick
}
