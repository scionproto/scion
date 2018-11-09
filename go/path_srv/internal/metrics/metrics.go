// Copyright 2018 Anapaya Systems
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

// Package metrics publishes information about PS operation.
package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

const (
	Namespace = "ps"
)

// Status used to differentiate between different "statuses" of a reply.
type Status string

const (
	Error    Status = "err"
	Invalid  Status = "invalid"
	OkCached Status = "ok_cached"
	Ok       Status = "ok"
)

type HandlerType string

const (
	SegReq HandlerType = "seg_req"
	SegReg HandlerType = "seg_reg"
	Rev    HandlerType = "rev"
	IfS    HandlerType = "if_state"
	SegSyn HandlerType = "seg_syn"
)

type HandlerMetrics struct {
	ReqsRecv     prometheus.Counter
	InvalidReqs  prometheus.Counter
	Errors       prometheus.Counter
	ResponseTime *prometheus.HistogramVec
}

func newMetricsForHandler(elem string, ht HandlerType, description string) *HandlerMetrics {
	constLabels := prometheus.Labels{"elem": elem}
	newC := func(name, help string) prometheus.Counter {
		return prom.NewCounter(Namespace, "", name, help, constLabels)
	}
	lNames := []string{"status"}
	newHVec := func(name, help string, buckets []float64) *prometheus.HistogramVec {
		return prom.NewHistogramVec(Namespace, "", name, help, constLabels, lNames, buckets)
	}
	return &HandlerMetrics{
		ReqsRecv: newC(fmt.Sprintf("%ss_recv_total", ht),
			fmt.Sprintf("Number of %s received.", description)),
		InvalidReqs: newC(fmt.Sprintf("%ss_invalid_total", ht),
			fmt.Sprintf("Number of invalid %s received.", description)),
		Errors: newC(fmt.Sprintf("%ss_errors_total", ht),
			fmt.Sprintf("Number of %s received that lead to an error.", description)),
		ResponseTime: newHVec(fmt.Sprintf("%s_time", ht), "Histogram for processing time.",
			[]float64{0.1, 0.2, 0.5, 2.0}),
	}
}

var (
	handlerMetrics map[HandlerType]*HandlerMetrics
)

func InitMetrics(elem string) {
	handlerMetrics = make(map[HandlerType]*HandlerMetrics)
	handlerMetrics[SegReq] = newMetricsForHandler(elem, SegReq, "segment requests")
	handlerMetrics[SegReg] = newMetricsForHandler(elem, SegReg, "segment registrations")
	handlerMetrics[Rev] = newMetricsForHandler(elem, Rev, "revocations")
	handlerMetrics[IfS] = newMetricsForHandler(elem, IfS, "ifstate info")
	handlerMetrics[SegSyn] = newMetricsForHandler(elem, SegSyn, "seg sync")
}

type HandlerFunc func() Status

func RunHandle(ht HandlerType, h HandlerFunc) {
	m, ok := handlerMetrics[ht]
	if !ok {
		panic("Invalid handler type: " + ht)
	}
	m.ReqsRecv.Inc()
	status := Ok
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		m.ResponseTime.WithLabelValues(string(status)).Observe(v)
	}))
	defer timer.ObserveDuration()
	status = h()
	switch status {
	case Error:
		m.Errors.Inc()
		return
	case Invalid:
		m.InvalidReqs.Inc()
		return
	case OkCached:
		return
	case Ok:
		return
	}
}
