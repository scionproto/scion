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

package periodic

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/log"
)

// A Task that has to be periodically executed.
type Task interface {
	// Run executes the task once, it should return within the context's timeout.
	Run(context.Context)
}

// Runner runs a task periodically.
type Runner struct {
	task     Task
	ticker   *time.Ticker
	interval time.Duration
	stop     chan struct{}
	stopped  chan struct{}
}

// StartPeriodicTask creates and starts a new Runner to run the given task peridiocally.
func StartPeriodicTask(task Task, interval time.Duration) *Runner {
	runner := &Runner{
		task:     task,
		ticker:   time.NewTicker(interval),
		interval: interval,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	go runner.runLoop()
	return runner
}

// Stop stops the peridioc execution of the Runner.
// If the task is currently running this method will block until it is done.
func (r *Runner) Stop() {
	r.ticker.Stop()
	close(r.stop)
	<-r.stopped
}

func (r *Runner) runLoop() {
	defer log.LogPanicAndExit()
	defer close(r.stopped)
	for {
		select {
		case <-r.ticker.C:
			ctx, cancelF := context.WithTimeout(context.Background(), r.interval)
			r.task.Run(ctx)
			cancelF()
		case <-r.stop:
			return
		}
	}
}
