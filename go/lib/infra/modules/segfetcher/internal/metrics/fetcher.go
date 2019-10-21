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

const RevSrcPathReply = "path_reply"

// Fetcher exposes all metrics for the fetcher.
type Fetcher interface {
	SegRequests(result string) prometheus.Counter
	RevocationsReceived(result string) prometheus.Counter
}

type fetcher struct {
	segRequest  *prometheus.CounterVec
	revocations *prometheus.CounterVec
}

// NewFetcher creates fetcher metrics struct.
func NewFetcher(namespace string) Fetcher {
	subst := "fetcher"
	requests := prom.SafeRegister(prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subst,
		Name:      "seg_requests_total",
		Help:      "The number of segment request sent, grouped by result",
	}, []string{prom.LabelResult})).(*prometheus.CounterVec)
	revocations := prom.SafeRegister(prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "recv_revocations_total",
		Help:      "The amount of revocations received by src type and result",
	}, []string{prom.LabelResult, prom.LabelSrc})).(*prometheus.CounterVec)
	return fetcher{
		segRequest:  requests,
		revocations: revocations,
	}
}

func (f fetcher) SegRequests(result string) prometheus.Counter {
	return f.segRequest.WithLabelValues(result)
}

func (f fetcher) RevocationsReceived(result string) prometheus.Counter {
	return f.revocations.WithLabelValues(result, RevSrcPathReply)
}
