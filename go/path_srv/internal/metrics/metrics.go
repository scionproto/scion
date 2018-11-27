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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	Namespace = "ps"
)

type ErrType string

const (
	ReqProgErr          ErrType = "prog_err"
	ReqPDbErr           ErrType = "path_db_err"
	ReqRevCacheErr      ErrType = "rev_cache_err"
	ReqTrustErr         ErrType = "trust_err"
	ReqMissingLocalSegs ErrType = "missing_local_segs_err"
	ReqNoRemoteSegs     ErrType = "missing_remote_segs_err"
	ReqNetworkErr       ErrType = "network_err"
	ReqInvalid          ErrType = "invalid_req"
)

// Status used to differentiate between different "statuses" of a reply.
type Status string

const (
	Err        Status = "err"
	ErrTimeout Status = "err_timeout"
	ErrInvalid Status = "err_invalid"
	OkCached   Status = "ok_cached"
	Ok         Status = "ok"
)

type HandlerType string

const (
	SegReq HandlerType = "seg_req"
	SegReg HandlerType = "seg_reg"
	Rev    HandlerType = "rev"
	IfS    HandlerType = "if_state"
	SegSyn HandlerType = "seg_syn"
)

var (
	handlerLatencies map[HandlerType]*prometheus.HistogramVec
	totalRequests    *prometheus.CounterVec
	errors           *prometheus.CounterVec
)

func InitMetrics(elem string) {
	constLabels := prometheus.Labels{"elem": elem}
	newCVec := func(name, help string, lNames []string) *prometheus.CounterVec {
		return prom.NewCounterVec(Namespace, "", name, help, constLabels, lNames)
	}
	newG := func(name, help string) prometheus.Gauge {
		return prom.NewGauge(Namespace, "", name, help, constLabels)
	}
	lNames := []string{"status"}
	newHVec := func(name, help string, buckets []float64) *prometheus.HistogramVec {
		return prom.NewHistogramVec(Namespace, "", name, help, constLabels, lNames, buckets)
	}
	// ps_base_labels is a special metric that always has the value `1`,
	// that is used to add labels to non-ps metrics.
	PSLabels := newG("base_labels", "Path service base labels.")
	PSLabels.Set(1)

	handlerLatencies = make(map[HandlerType]*prometheus.HistogramVec)
	addLatency := func(ht HandlerType) {
		handlerLatencies[ht] = newHVec(fmt.Sprintf("%s_time", ht),
			fmt.Sprintf("%s processing time", ht),
			[]float64{0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0})
	}
	addLatency(SegReq)
	addLatency(SegReg)
	addLatency(Rev)
	addLatency(IfS)
	addLatency(SegSyn)
	totalRequests = newCVec("requests_total", "Total number of requests", []string{"handler"})
	errors = newCVec("errors_total", "Total numbers of errors by handler, type, remote ISD",
		[]string{"handler", "type", "remote_isd"})
}

func ErrInc(ht HandlerType, err ErrType, isd addr.ISD) {
	errors.WithLabelValues(string(ht), string(err), fmt.Sprintf("%d", isd)).Inc()
}

type HandlerFunc func() Status

func RunHandle(ht HandlerType, h HandlerFunc) {
	totalRequests.WithLabelValues(string(ht)).Inc()
	l, ok := handlerLatencies[ht]
	if !ok {
		panic("Invalid handler type: " + ht)
	}
	status := Ok
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		l.WithLabelValues(string(status)).Observe(v)
	}))
	defer timer.ObserveDuration()
	status = h()
}
