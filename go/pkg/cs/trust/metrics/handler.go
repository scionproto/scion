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

// HandlerLabels defines the handler labels.
type HandlerLabels struct {
	Client  string
	ReqType string
	Result  string
}

// Labels returns the list of labels.
func (l HandlerLabels) Labels() []string {
	return []string{"client", "req_type", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l HandlerLabels) Values() []string {
	return []string{l.Client, l.ReqType, l.Result}
}

// WithResult returns the handler labels with the modified result.
func (l HandlerLabels) WithResult(result string) HandlerLabels {
	l.Result = result
	return l
}

type handler struct {
	Requests *prometheus.CounterVec
}

func newHandler() handler {
	return handler{
		Requests: prom.NewCounterVecWithLabels(Namespace, "", "received_requests_total",
			"Number of requests served by the trust engine", HandlerLabels{}),
	}
}

func (h *handler) Request(l HandlerLabels) prometheus.Counter {
	return h.Requests.WithLabelValues(l.Values()...)
}
