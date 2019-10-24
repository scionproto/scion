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
	Namespace          = "lib_infra"
	subsystemMessenger = "messenger"
	subsystemAdapter   = "adapter"
)

// Result values
const (
	OkSuccess        = prom.Success
	ErrRead          = "err_read"
	ErrInvalidReq    = prom.ErrInvalidReq
	ErrVerify        = prom.ErrVerify
	ErrParse         = prom.ErrParse
	ErrValidate      = prom.ErrValidate
	ErrNotClassified = prom.ErrNotClassified
)

var resultLabel = []string{prom.LabelResult}

// Metric accessors.
var (
	Dispatcher = newDispatcher()
	Adapter    = newAdapter()
)

// ResultLabels contains the label for infra dispatcher reads.
type ResultLabels struct {
	Result string
}

// Labels returns the list of labels.
func (l ResultLabels) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l ResultLabels) Values() []string {
	return []string{l.Result}
}

type dispatcher struct {
	reads     *prometheus.CounterVec
	readSizes prometheus.Histogram
}

func newDispatcher() dispatcher {
	return dispatcher{
		reads: prom.NewCounterVec(Namespace, subsystemMessenger, "reads_total",
			"Total number of Read calls.", ResultLabels{}.Labels()),
		readSizes: prom.NewHistogram(Namespace, subsystemMessenger, "read_size_bytes",
			"Size of successful reads.", prom.DefaultSizeBuckets),
	}
}

func (d dispatcher) Reads(l ResultLabels) prometheus.Counter {
	return d.reads.WithLabelValues(l.Values()...)
}

func (d dispatcher) ReadSizes() prometheus.Histogram {
	return d.readSizes
}

type adapter struct {
	errors *prometheus.CounterVec
}

func newAdapter() adapter {
	return adapter{
		errors: prom.NewCounterVec(Namespace, subsystemAdapter, "errors_total",
			"Total number of adapter errors.", ResultLabels{}.Labels()),
	}
}

func (a adapter) Errors(l ResultLabels) prometheus.Counter {
	return a.errors.WithLabelValues(l.Values()...)
}
