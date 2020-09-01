// Copyright 2019 ETH Zurich
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

const (
	// Namespace is the metrics namespace for the SCIOND client API.
	Namespace = "lib_sciond"

	subsystemConn       = "conn"
	subsystemPath       = "path"
	subsystemASInfo     = "as_info"
	subsystemIFInfo     = "if_info"
	subsystemSVCInfo    = "service_info"
	subsystemRevocation = "revocation"
)

// Result values
const (
	OkSuccess        = prom.Success
	ErrTimeout       = prom.ErrTimeout
	ErrNotClassified = prom.ErrNotClassified
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
	// Conns contains metrics for connections to SCIOND.
	Conns = newConn()
)

// Request is the generic metric for requests.
type Request struct {
	count *prometheus.CounterVec
}

func (r *Request) CounterVec() *prometheus.CounterVec {
	return r.count
}

// Inc increases the metric count. The result parameter is used to label the increment.
func (r Request) Inc(result string) {
	r.count.WithLabelValues(result).Inc()
}

func newConn() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemConn, "connections_total",
			"The amount of SCIOND connection attempts.", resultLabel{}),
	}
}

func newPathRequest() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemPath, "requests_total",
			"The amount of Path requests sent.", resultLabel{}),
	}
}

func newRevocation() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemRevocation, "requests_total",
			"The amount of Revocation requests sent.", resultLabel{}),
	}
}

func newASInfoRequest() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemASInfo, "requests_total",
			"The amount of AS info requests sent.", resultLabel{}),
	}
}

func newSVCInfo() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemSVCInfo, "requests_total",
			"The amount of SVC info requests sent.", resultLabel{}),
	}
}

func newIFInfo() Request {
	return Request{
		count: prom.NewCounterVecWithLabels(Namespace, subsystemIFInfo, "requests_total",
			"The amount of IF info requests sent.", resultLabel{}),
	}
}
