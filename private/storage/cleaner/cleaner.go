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

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/private/periodic"
)

// ExpiredDeleter is used to delete expired data.
type ExpiredDeleter func(ctx context.Context) (int, error)

var _ periodic.Task = (*Cleaner)(nil)

// Cleaner is a periodic.Task implementation that deletes expired data.
type Cleaner struct {
	deleter   ExpiredDeleter
	subsystem string
	metrics   Metrics
}

// Metrics contains the metrics for a cleaner.
type Metrics struct {
	// ErrorsTotal reports the total number of errors during cleaning.
	ErrorsTotal metrics.Counter
	// RunsTotal reports the total number of successful runs.
	RunsTotal metrics.Counter
	// DeletedTotal reports the total number of deleted entries.
	DeletedTotal metrics.Counter
}

// New returns a new cleaner task that deletes expired data using deleter.
func New(deleter ExpiredDeleter, subsystem string, metrics Metrics) *Cleaner {
	return &Cleaner{
		deleter:   deleter,
		subsystem: subsystem,
		metrics:   metrics,
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
		metrics.CounterInc(c.metrics.ErrorsTotal)
		return
	}
	if count > 0 {
		logger.Info("Deleted expired", "subsystem", c.subsystem, "count", count)
		metrics.CounterAdd(c.metrics.DeletedTotal, float64(count))
	}
	metrics.CounterInc(c.metrics.RunsTotal)
}
