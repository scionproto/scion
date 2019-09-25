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

// Namespace is the metrics namespace for the infra discovery module.
const Namespace = "idiscovery"

// Topology types.
const (
	Static  = "static"
	Dynamic = "dynamic"
)

// Result labels.
const (
	Success      = prom.Success
	OkIgnored    = "ok_ignored"
	ErrRequest   = "err_request"
	ErrUpdate    = "err_update"
	ErrWriteFile = "err_write_file"
)

// Fetcher is the single-instance struct to get prometheus counters.
var Fetcher = newFetcher()

// FetcherLabels defines the requests label set.
type FetcherLabels struct {
	Static bool
	Result string
}

// Labels returns the name of the labels in correct order.
func (l FetcherLabels) Labels() []string {
	return []string{"type", "result"}
}

// Values returns the values of the label in correct order.
func (l FetcherLabels) Values() []string {
	if l.Static {
		return []string{Static, l.Result}
	}
	return []string{Dynamic, l.Result}
}

// WithResult returns the label set with the modified result.
func (l FetcherLabels) WithResult(result string) FetcherLabels {
	l.Result = result
	return l
}

type fetcher struct {
	sent, file *prometheus.CounterVec
}

func newFetcher() fetcher {
	return fetcher{
		sent: prom.NewCounterVec(Namespace, "", "sent_requests_total",
			"The total number of requests sent to the discovey service", FetcherLabels{}.Labels()),
		file: prom.NewCounterVec(Namespace, "", "file_writes_total",
			"The total number of file writes on updated topology", FetcherLabels{}.Labels()),
	}
}

// Sent returns the prometheus counter.
func (r fetcher) Sent(l FetcherLabels) prometheus.Counter {
	return r.sent.WithLabelValues(l.Values()...)
}

// File returns the prometheus counter.
func (r fetcher) File(l FetcherLabels) prometheus.Counter {
	return r.file.WithLabelValues(l.Values()...)
}
