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
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/proto"
)

type result string

const (
	// Success indicates a successful result.
	Success result = "success"
	// CreateErr indicates an error during beacon creation.
	CreateErr result = "creation_err"
	// SendErr indicates an error during sending the beacon.
	SendErr result = "send_err"
	// InvalidErr indicates that incoming beacon was invalid.
	InvalidErr result = "invalid_err"
	// VerifyErr indicates that incoming beacon wasn't verified.
	VerifyErr result = "varify_err"
	// InsertErr indicated that incoming beacon couldn't be inserted.
	InsertErr result = "insert_err"
	// Prefiltered indicates that incoming beacon was prefiltered.
	Prefiltered result = "prefiltered"
)

var (
	receiverOnce   sync.Once
	receiver       *Receiver
	propagatorOnce sync.Once
	propagator     *Propagator
	originatorOnce sync.Once
	originator     *Originator
	registrarOnce  sync.Once
	registrar      *Registrar
)

// Receiver holds the metrics about incoming beacons.
type Receiver struct {
	totalBeacons prometheus.CounterVec
}

// InitReceiver initializes the receiver metrics and returns a handle.
func InitReceiver() *Receiver {
	receiverOnce.Do(func() {
		receiver = newReceiver()
	})
	return receiver
}

func newReceiver() *Receiver {
	ns := "beacon_receiver"
	return &Receiver{
		totalBeacons: *prom.NewCounterVec(
			ns, "", "beacons_total", "Number of beacons received",
			[]string{"in_ifid", "result"}),
	}
}

// IncTotalBeacons increments the total beacon count.
func (m *Receiver) IncTotalBeacons(in common.IFIDType, res result) {
	if m == nil {
		return
	}
	m.totalBeacons.With(prometheus.Labels{
		"in_ifid": ifidToString(in),
		"result":  string(res),
	}).Inc()
}

// Propagator holds the propagation metrics.
type Propagator struct {
	totalBeacons     prometheus.CounterVec
	totalIntfTime    prometheus.CounterVec
	totalTime        prometheus.Counter
	totalInternalErr prometheus.Counter
}

// InitPropagator initializes the propagator metrics and returns a handle.
func InitPropagator() *Propagator {
	propagatorOnce.Do(func() {
		propagator = newPropagator()
	})
	return propagator
}

func newPropagator() *Propagator {
	ns := "beacon_propagator"
	return &Propagator{
		totalBeacons: *prom.NewCounterVec(ns, "", "beacons_total", "Number of beacons propagated",
			[]string{"start_ia", "in_ifid", "eg_ifid", "result"}),
		totalIntfTime: *prom.NewCounterVec(ns, "", "time_interface_seconds_total",
			"Total time spent per egress interface", []string{"start_ia", "in_ifid", "eg_ifid"}),
		totalTime:        prom.NewCounter(ns, "", "time_seconds_total", "Total time spent"),
		totalInternalErr: prom.NewCounter(ns, "", "internal_errors_total", "Total internal errors"),
	}
}

// AddTotalTime adds the time since start to the total time.
func (m *Propagator) AddTotalTime(start time.Time) {
	if m == nil {
		return
	}
	m.totalTime.Add(time.Since(start).Seconds())
}

// IncTotalBeacons increments the total beacon count.
func (m *Propagator) IncTotalBeacons(start addr.IA, in, eg common.IFIDType,
	res result) {

	if m == nil {
		return
	}
	m.totalBeacons.With(prometheus.Labels{"start_ia": start.String(), "in_ifid": ifidToString(in),
		"eg_ifid": ifidToString(eg), "result": string(res)}).Inc()
}

// AddIntfTime adds the time since start to the interface time.
func (m *Propagator) AddIntfTime(ia addr.IA, in, eg common.IFIDType, start time.Time) {
	if m == nil {
		return
	}
	m.totalIntfTime.With(prometheus.Labels{"start_ia": ia.String(), "in_ifid": ifidToString(in),
		"eg_ifid": ifidToString(eg)}).Add(time.Since(start).Seconds())
}

// IncInternalErr increments the internal error count.
func (m *Propagator) IncInternalErr() {
	if m == nil {
		return
	}
	m.totalInternalErr.Inc()
}

// Registrar holds the core registrar metrics.
type Registrar struct {
	totalBeacons     prometheus.CounterVec
	totalTime        prometheus.CounterVec
	totalInternalErr prometheus.CounterVec
}

// InitRegistrar initializes the registrar metrics and returns a handle.
func InitRegistrar() *Registrar {
	registrarOnce.Do(func() {
		registrar = newRegistrar()
	})
	return registrar
}

func newRegistrar() *Registrar {
	ns := "beacon_registrar"
	return &Registrar{
		totalBeacons: *prom.NewCounterVec(ns, "", "beacons_total", "Number of beacons registered",
			[]string{"start_ia", "in_ifid", "type", "result"}),
		totalTime: *prom.NewCounterVec(ns, "", "time_seconds_total", "Total time spent",
			[]string{"type"}),
		totalInternalErr: *prom.NewCounterVec(ns, "", "internal_errors_total",
			"Total internal errors", []string{"type"}),
	}
}

// AddTotalTime adds the time since start to the total time.
func (m *Registrar) AddTotalTime(t proto.PathSegType, start time.Time) {
	if m == nil {
		return
	}
	m.totalTime.With(prometheus.Labels{"type": t.String()}).Add(time.Since(start).Seconds())
}

// IncTotalBeacons increments the total beacon count.
func (m *Registrar) IncTotalBeacons(t proto.PathSegType, start addr.IA, in common.IFIDType,
	res result) {

	if m == nil {
		return
	}
	m.totalBeacons.With(prometheus.Labels{"type": t.String(), "start_ia": start.String(),
		"in_ifid": ifidToString(in), "result": string(res)}).Inc()
}

// IncInternalErr increments the internal error count.
func (m *Registrar) IncInternalErr(t proto.PathSegType) {
	if m == nil {
		return
	}
	m.totalInternalErr.With(prometheus.Labels{"type": t.String()}).Inc()
}

// Originator holds the originator metrics.
type Originator struct {
	totalBeacons     prometheus.CounterVec
	totalTime        prometheus.Counter
	totalInternalErr prometheus.Counter
}

// InitOriginator initializes the originator metrics and returns a handle.
func InitOriginator() *Originator {
	originatorOnce.Do(func() {
		originator = newOriginator()
	})
	return originator
}

func newOriginator() *Originator {
	ns := "beacon_originator"
	return &Originator{
		totalBeacons: *prom.NewCounterVec(ns, "", "beacons_total", "Number of beacons originated",
			[]string{"eg_ifid", "result"}),
		totalTime:        prom.NewCounter(ns, "", "time_seconds_total", "Total time spent"),
		totalInternalErr: prom.NewCounter(ns, "", "internal_errors_total", "Total internal errors"),
	}
}

// AddTotalTime adds the time since start to the total time.
func (m *Originator) AddTotalTime(start time.Time) {
	if m == nil {
		return
	}
	m.totalTime.Add(time.Since(start).Seconds())
}

// IncTotalBeacons increments the total beacon count.
func (m *Originator) IncTotalBeacons(eg common.IFIDType, res result) {
	if m == nil {
		return
	}
	m.totalBeacons.With(prometheus.Labels{"eg_ifid": ifidToString(eg), "result": string(res)}).Inc()
}

// IncInternalErr increments the internal error count.
func (m *Originator) IncInternalErr() {
	if m == nil {
		return
	}
	m.totalInternalErr.Inc()
}

func ifidToString(ifid common.IFIDType) string {
	return strconv.FormatUint(uint64(ifid), 10)
}
