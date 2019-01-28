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

package infra

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	PromSrcASLocal   = "as_local"
	PromSrcISDLocal  = "isd_local"
	PromSrcISDRemote = "isd_remote"
	PromSrcUnknown   = "unknown"
)

// HandlerMetrics contains the standard metrics for a handler.
type HandlerMetrics struct {
	RequestsTotal  *prometheus.CounterVec
	RequestLatency *prometheus.HistogramVec
	ResultsTotal   *prometheus.CounterVec
}

// HandlerResult contains a result label and a status label.
type HandlerResult struct {
	Result string
	Status string
}

var (
	MetricsErrInternal = &HandlerResult{Result: "err_internal", Status: prom.StatusErr}
	MetricsErrInvalid  = &HandlerResult{Result: "err_invalid_req", Status: prom.StatusErr}

	metricsErrMsger        = &HandlerResult{Result: "err_msger", Status: prom.StatusErr}
	metricsErrMsgerTimeout = &HandlerResult{Result: "err_msger_to", Status: prom.StatusTimeout}

	metricsErrTrustDB        = &HandlerResult{Result: "err_trustdb", Status: prom.StatusErr}
	metricsErrTrustDBTimeout = &HandlerResult{Result: "err_trustdb_to", Status: prom.StatusTimeout}

	metricsErrTS        = &HandlerResult{Result: "err_truststore", Status: prom.StatusErr}
	metricsErrTSTimeout = &HandlerResult{Result: "err_truststore_to", Status: prom.StatusTimeout}

	MetricsResultOk = &HandlerResult{Result: prom.ResultOk, Status: prom.StatusOk}
)

func MetricsErrTrustDB(err error) *HandlerResult {
	return metricsErrWithTimeout(err, metricsErrTrustDBTimeout, metricsErrTrustDB)
}

func MetricsErrMsger(err error) *HandlerResult {
	return metricsErrWithTimeout(err, metricsErrMsgerTimeout, metricsErrMsger)
}

func MetricsErrTrustStore(err error) *HandlerResult {
	return metricsErrWithTimeout(err, metricsErrTSTimeout, metricsErrTS)
}

func metricsErrWithTimeout(err error, timeoutResult, result *HandlerResult) *HandlerResult {
	if common.IsTimeoutErr(err) {
		return timeoutResult
	}
	return result
}
