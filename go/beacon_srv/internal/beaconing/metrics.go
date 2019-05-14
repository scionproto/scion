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

package beaconing

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

type metricsResult string

const (
	metricsSuccess   metricsResult = "success"
	metricsCreateErr metricsResult = "creation_err"
	metricsSendErr   metricsResult = "send_err"
)

type propagatorMetrics struct {
	totalBeacons     prometheus.CounterVec
	totalIntfTime    prometheus.CounterVec
	totalTime        prometheus.Counter
	totalInternalErr prometheus.Counter
}

func newPropagatorMetrics() *propagatorMetrics {
	ns := "beacon_propagator"
	return &propagatorMetrics{
		totalBeacons: *prom.NewCounterVec(ns, "", "total_beacons", "Number of beacons propagated",
			[]string{"start_ia", "in_ifid", "eg_ifid", "result"}),
		totalIntfTime: *prom.NewCounterVec(ns, "", "total_time_intf",
			"Total time spent per egress interface", []string{"start_ia", "in_ifid", "eg_ifid"}),
		totalTime:        prom.NewCounter(ns, "", "total_time", "Total time spent"),
		totalInternalErr: prom.NewCounter(ns, "", "total_internal_errors", "Total internal errors"),
	}
}

func (m *propagatorMetrics) AddTotalTime(start time.Time) {
	if m == nil {
		return
	}
	m.totalTime.Add(time.Since(start).Seconds())
}

func (m *propagatorMetrics) IncTotalBeacons(start addr.IA, in, eg common.IFIDType,
	res metricsResult) {

	if m == nil {
		return
	}
	m.totalBeacons.With(prometheus.Labels{"start_ia": start.String(), "in_ifid": iota(in),
		"eg_ifid": iota(eg), "result": string(res)}).Inc()
}

func (m *propagatorMetrics) AddIntfTime(ia addr.IA, in, eg common.IFIDType, start time.Time) {
	if m == nil {
		return
	}
	m.totalIntfTime.With(prometheus.Labels{"start_ia": ia.String(), "in_ifid": iota(in),
		"eg_ifid": iota(eg)}).Add(time.Since(start).Seconds())
}

func (m *propagatorMetrics) IncInternalErr() {
	if m == nil {
		return
	}
	m.totalInternalErr.Inc()
}

type registrarMetrics struct {
	totalBeacons     prometheus.CounterVec
	totalTime        prometheus.Counter
	totalInternalErr prometheus.Counter
}

func newRegistrarMetrics() *registrarMetrics {
	ns := "beacon_registrar"
	return &registrarMetrics{
		totalBeacons: *prom.NewCounterVec(ns, "", "total_beacons", "Number of beacons registered",
			[]string{"start_ia", "in_ifid", "result"}),
		totalTime:        prom.NewCounter(ns, "", "total_time", "Total time spent"),
		totalInternalErr: prom.NewCounter(ns, "", "total_internal_errors", "Total internal errors"),
	}
}

func (m *registrarMetrics) AddTotalTime(start time.Time) {
	if m == nil {
		return
	}
	m.totalTime.Add(time.Since(start).Seconds())
}

func (m *registrarMetrics) IncTotalBeacons(start addr.IA, in common.IFIDType, res metricsResult) {
	if m == nil {
		return
	}
	m.totalBeacons.With(prometheus.Labels{"start_ia": start.String(), "in_ifid": iota(in),
		"result": string(res)}).Inc()
}

func (m *registrarMetrics) IncInternalErr() {
	if m == nil {
		return
	}
	m.totalInternalErr.Inc()
}

type originatorMetrics struct {
	totalBeacons     prometheus.CounterVec
	totalTime        prometheus.Counter
	totalInternalErr prometheus.Counter
}

func newOriginatorMetrics() *originatorMetrics {
	ns := "beacon_originator"
	return &originatorMetrics{
		totalBeacons: *prom.NewCounterVec(ns, "", "total_beacons", "Number of beacons originated",
			[]string{"eg_ifid", "result"}),
		totalTime:        prom.NewCounter(ns, "", "total_time", "Total time spent"),
		totalInternalErr: prom.NewCounter(ns, "", "total_internal_errors", "Total internal errors"),
	}
}

func (m *originatorMetrics) AddTotalTime(start time.Time) {
	if m == nil {
		return
	}
	m.totalTime.Add(time.Since(start).Seconds())
}

func (m *originatorMetrics) IncTotalBeacons(eg common.IFIDType, res metricsResult) {
	if m == nil {
		return
	}
	m.totalBeacons.With(prometheus.Labels{"eg_ifid": iota(eg), "result": string(res)}).Inc()
}

func (m *originatorMetrics) IncInternalErr() {
	if m == nil {
		return
	}
	m.totalInternalErr.Inc()
}

func iota(ifid common.IFIDType) string {
	return strconv.FormatUint(uint64(ifid), 10)
}
