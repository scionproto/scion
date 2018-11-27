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

package cleaner

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

const (
	subsystem = "cleaner"
)

var (
	Errors   *prometheus.CounterVec
	DelCount *prometheus.CounterVec
)

func InitMetrics(namespace string, constLabels prometheus.Labels) {
	labelNames := []string{"name"}
	newCVec := func(name, help string) *prometheus.CounterVec {
		return prom.NewCounterVec(namespace, subsystem, name, help, constLabels, labelNames)
	}
	Errors = newCVec("errors_total", "Number of errors.")
	DelCount = newCVec("deleted_total", "Number of deleted records.")
}

type metrics struct {
	errors   prometheus.Counter
	delcount prometheus.Counter
}

func newMetrics(name string) *metrics {
	if Errors == nil || DelCount == nil {
		return nil
	}
	l := make(prometheus.Labels)
	l["name"] = name
	return &metrics{
		errors:   Errors.With(l),
		delcount: DelCount.With(l),
	}
}

func (m *metrics) Error() {
	if m != nil {
		m.errors.Inc()
	}
}

func (m *metrics) DelCount(c int) {
	if m != nil {
		m.delcount.Add(float64(c))
	}
}
