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
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	// metricSubsystem is the subsystem under which metrics are published for the cleaner.
	metricSubsystem = "cleaner"
)

var registry = metricsRegistry{registered: make(map[string]*metric)}

// ExpiredDeleter is used to delete expired data.
type ExpiredDeleter func(ctx context.Context) (int, error)

var _ periodic.Task = (*Cleaner)(nil)

// Cleaner is a periodic.Task implementation that deletes expired data.
type Cleaner struct {
	deleter   ExpiredDeleter
	subsystem string
	metric    *metric
}

// New returns a new cleaner task that deletes expired data using deleter.
func New(deleter ExpiredDeleter, subsystem string) *Cleaner {
	return &Cleaner{
		deleter:   deleter,
		subsystem: subsystem,
		metric:    registry.register(subsystem),
	}
}

// Name returns the tasks name.
func (c *Cleaner) Name() string {
	return fmt.Sprintf("%s_cleaner", c.subsystem)
}

// Run deletes expired entries using the deleter func.
func (c *Cleaner) Run(ctx context.Context) {
	count, err := c.deleter(ctx)
	logger := log.FromCtx(ctx)
	if err != nil {
		logger.Error("Failed to delete", "subsystem", c.subsystem, "err", err)
		c.metric.resultsTotal.WithLabelValues("err").Inc()
		return
	}
	if count > 0 {
		logger.Info("Deleted expired", "subsystem", c.subsystem, "count", count)
		c.metric.deletedTotal.Add(float64(count))
	}
	c.metric.resultsTotal.WithLabelValues("ok").Inc()
}

type metricsRegistry struct {
	mu         sync.Mutex
	registered map[string]*metric
}

func (m *metricsRegistry) register(namespace string) *metric {
	m.mu.Lock()
	defer m.mu.Unlock()
	if metric, ok := m.registered[namespace]; ok {
		return metric
	}
	m.registered[namespace] = &metric{
		resultsTotal: *prom.NewCounterVec(namespace, metricSubsystem, "results_total",
			"Results of running the cleaner, either ok or err", []string{"result"}),
		deletedTotal: prom.NewCounter(namespace, metricSubsystem, "deleted_total",
			"Number of deleted entries total."),
	}
	return m.registered[namespace]
}

type metric struct {
	resultsTotal prometheus.CounterVec
	deletedTotal prometheus.Counter
}
