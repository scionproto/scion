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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	PromSrcASLocal   = "as_local"
	PromSrcISDLocal  = "isd_local"
	PromSrcISDRemote = "isd_remote"
	PromSrcUnknown   = "unknown"
)

// HandlerResult contains a result label and a status label.
type HandlerResult struct {
	// Result is the label used for the result metric.
	Result string
	// Status is one of prom.StatusOk, prom.StatusErr, prom.StatusTimeout it is used for the latency
	// histogram. This is a reduced view of the result, so that we don't get too many timeseries on
	// the histogram.
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

	metricsErrRevCache   = &HandlerResult{Result: "err_revcache", Status: prom.StatusErr}
	metricsErrRevCacheTo = &HandlerResult{Result: "err_revcache_to", Status: prom.StatusTimeout}

	MetricsResultOk = &HandlerResult{Result: prom.ResultOk, Status: prom.StatusOk}
)

func MetricsErrTrustDB(err error) *HandlerResult {
	return metricsErrWithTimeout(err, metricsErrTrustDBTimeout, metricsErrTrustDB)
}

func MetricsErrRevCache(err error) *HandlerResult {
	return metricsErrWithTimeout(err, metricsErrRevCacheTo, metricsErrRevCache)
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
