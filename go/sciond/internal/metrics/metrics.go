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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	// Namespace is the metrics namespace for sciond.
	Namespace = "sd"

	subsystemPath       = "path"
	subsystemASInfo     = "as_info"
	subsystemIFInfo     = "if_info"
	subsystemSVCInfo    = "service_info"
	subsystemRevocation = "revocation"
)

// Revocation sources
const (
	RevSrcNotification = "notification"
	RevSrcSCMP         = "scmp"
	RevSrcPathReply    = "path_reply"
)

// Result values
const (
	OkSuccess        = prom.Success
	ErrInternal      = prom.ErrInternal
	ErrNetwork       = prom.ErrNetwork
	ErrDB            = prom.ErrDB
	ErrTimeout       = prom.ErrTimeout
	ErrParse         = prom.ErrParse
	ErrNotClassified = prom.ErrNotClassified
)

// Metric accessors.
var (
	// PathRequests contains metrics for path requests.
	PathRequests = newPathRequest()
	// Revocations contains metrics for revocations.
	Revocations = newRevocation()
	// ASInfos contains metrics for AS info requests.
	ASInfos = newASInfoRequest()
	// IFInfos contains metrics for IF info requests.
	IFInfos = newIFInfo()
	// SVCInfos contains metrics for SVC info requests.
	SVCInfos = newSVCInfo()
)

type resultLabel struct {
	Result string
}

// Labels returns the labels.
func (l resultLabel) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the values for the labels.
func (l resultLabel) Values() []string {
	return []string{l.Result}
}

// PathRequestLabels are the labels for path requests metrics.
type PathRequestLabels struct {
	Result string
	Dst    addr.ISD
}

// Labels returns the labels.
func (l PathRequestLabels) Labels() []string {
	return []string{prom.LabelResult, prom.LabelDst}
}

// Values returns the values for the labels.
func (l PathRequestLabels) Values() []string {
	return []string{l.Result, l.Dst.String()}
}

// WithResult returns the labels with the result set.
func (l PathRequestLabels) WithResult(result string) PathRequestLabels {
	l.Result = result
	return l
}

// RevocationLabels are the labels for revocation metrics.
type RevocationLabels struct {
	Result string
	Src    string
}

// Labels returns the labels.
func (l RevocationLabels) Labels() []string {
	return []string{prom.LabelResult, prom.LabelSrc}
}

// Values returns the values for the labels.
func (l RevocationLabels) Values() []string {
	return []string{l.Result, l.Src}
}

// WithResult returns the labels with the result set.
func (l RevocationLabels) WithResult(result string) RevocationLabels {
	l.Result = result
	return l
}

// PathRequest contains the metrics for path requests.
type PathRequest struct {
	count   *prometheus.CounterVec
	latency *prometheus.HistogramVec
}

func newPathRequest() PathRequest {
	return PathRequest{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemPath, "requests_total",
			"The amount of path requests received.", PathRequestLabels{}),
		latency: prom.NewHistogramVec(Namespace, subsystemPath, "request_duration_seconds",
			"Time to handle path requests.", resultLabel{}.Labels(), prom.DefaultLatencyBuckets),
	}
}

// Start registers the start time of a path request and returns a callback that
// should be called at the end of processing the request.
func (r PathRequest) Start() func(PathRequestLabels) {
	start := time.Now()
	return func(l PathRequestLabels) {
		r.count.WithLabelValues(l.Values()...).Inc()
		r.latency.WithLabelValues(l.Result).Observe(time.Since(start).Seconds())
	}
}

// Revocation contains the metrics for revocation processing.
type Revocation struct {
	count   *prometheus.CounterVec
	latency *prometheus.HistogramVec
}

func newRevocation() Revocation {
	return Revocation{
		count: prom.NewCounterVecWithLabels(Namespace, "", "received_revocations_total",
			"The amount of revocations received.",
			RevocationLabels{Result: OkSuccess, Src: RevSrcNotification}),
		latency: prom.NewHistogramVec(Namespace, subsystemRevocation,
			"notification_duration_seconds", "Time to process revocation notifications.",
			resultLabel{}.Labels(), prom.DefaultLatencyBuckets),
	}
}

// Count returns the counter for revocations, this should only be incremented if
// Start is not used.
func (r Revocation) Count(l RevocationLabels) prometheus.Counter {
	return r.count.WithLabelValues(l.Values()...)
}

// Start registers the start time of a revocation notification and returns a
// callback that should be called at the end of processing the notification.
func (r Revocation) Start() func(RevocationLabels) {
	start := time.Now()
	return func(l RevocationLabels) {
		r.count.WithLabelValues(l.Values()...).Inc()
		r.latency.WithLabelValues(l.Result).Observe(time.Since(start).Seconds())
	}
}

// Request is the generic metric for requests.
type Request struct {
	count   *prometheus.CounterVec
	latency *prometheus.HistogramVec
}

// Start registers the start time of a request and returns a callback that
// should be called at the end of processing the request.
func (r Request) Start() func(string) {
	start := time.Now()
	return func(result string) {
		r.count.WithLabelValues(result).Inc()
		r.latency.WithLabelValues(result).Observe(time.Since(start).Seconds())
	}
}

func newASInfoRequest() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemASInfo, "requests_total",
			"The amount of AS info requests received.", resultLabel{}),
		latency: prom.NewHistogramVec(Namespace, subsystemASInfo, "request_duration_seconds",
			"Time to handle AS info requests.", resultLabel{}.Labels(), prom.DefaultLatencyBuckets),
	}
}

func newSVCInfo() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemSVCInfo, "requests_total",
			"The amount of SVC info requests received.", resultLabel{}),
		latency: prom.NewHistogramVec(Namespace, subsystemSVCInfo, "request_duration_seconds",
			"Time to handle SVC info requests.",
			resultLabel{}.Labels(), prom.DefaultLatencyBuckets),
	}
}

func newIFInfo() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemIFInfo, "requests_total",
			"The amount of IF info requests received.", resultLabel{}),
		latency: prom.NewHistogramVec(Namespace, subsystemIFInfo, "request_duration_seconds",
			"Time to handle IF info requests.", resultLabel{}.Labels(), prom.DefaultLatencyBuckets),
	}
}
