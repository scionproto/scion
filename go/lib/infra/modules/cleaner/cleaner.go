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

package cleaner

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	// MetricsNamespace is the namespace under which metrics are published for
	// the cleaner.
	MetricsNamespace = "cleaner"
)

// ExpiredDeleter is used to delete expired data.
type ExpiredDeleter func(ctx context.Context) (int, error)

var _ periodic.Task = (*Cleaner)(nil)

// Cleaner is a periodic.Task implementation that deletes expired data.
type Cleaner struct {
	deleter ExpiredDeleter
	logger  log.Logger

	resultsTotal *prometheus.CounterVec
	deletedTotal prometheus.Counter
}

// New returns a new cleaner task that delete expired data from deleter.
func New(deleter ExpiredDeleter, label string) *Cleaner {
	return &Cleaner{
		deleter: deleter,
		logger:  log.New("label", label),
		resultsTotal: prom.NewCounterVec(MetricsNamespace, label, "results_total",
			"Results of running the cleaner, either ok or err", []string{"result"}),
		deletedTotal: prom.NewCounter(MetricsNamespace, label, "deleted_total",
			"Number of deleted entries total."),
	}
}

// Run deletes expired entries using the deleter func.
func (c *Cleaner) Run(ctx context.Context) {
	result := "ok"
	defer c.resultsTotal.WithLabelValues(result).Inc()
	count, err := c.deleter(ctx)
	if err != nil {
		c.logger.Error("[Cleaner] Failed to delete", "err", err)
		result = "err"
		return
	}
	if count > 0 {
		c.logger.Info("[Cleaner] Deleted expired", "count", count)
		c.deletedTotal.Add(float64(count))
	}
}
