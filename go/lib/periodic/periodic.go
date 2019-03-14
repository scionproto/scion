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

// Ticker interface to improve testability of this periodic task code.
type Ticker interface {
	Chan() <-chan time.Time
	Stop()
}

type defaultTicker struct {
	*time.Ticker
}

func (t *defaultTicker) Chan() <-chan time.Time {
	return t.C
}

// NewTicker returns a new Ticker with time.Ticker as implementation.
func NewTicker(d time.Duration) Ticker {
	return &defaultTicker{
		Ticker: time.NewTicker(d),
	}
}

// A Task that has to be periodically executed.
type Task interface {
	// Run executes the task once, it should return within the context's timeout.
	Run(context.Context)
}

// Runner runs a task periodically.
type Runner struct {
	task         Task
	ticker       Ticker
	timeout      time.Duration
	stop         chan struct{}
	loopFinished chan struct{}
	ctx          context.Context
	cancelF      context.CancelFunc
	trigger      chan struct{}
}

// StartPeriodicTask creates and starts a new Runner to run the given task peridiocally.
// The ticker regulates the periodicity. The timeout is used for the context timeout of the task.
// The timeout can be larger than the periodicity of the ticker. That means if a tasks takes a long
// time it will be immediately retriggered.
func StartPeriodicTask(task Task, ticker Ticker, timeout time.Duration) *Runner {
	ctx, cancelF := context.WithCancel(context.Background())
	runner := &Runner{
		task:         task,
		ticker:       ticker,
		timeout:      timeout,
		stop:         make(chan struct{}),
		loopFinished: make(chan struct{}),
		ctx:          ctx,
		cancelF:      cancelF,
		trigger:      make(chan struct{}),
	}
	go func() {
		defer log.LogPanicAndExit()
		runner.runLoop()
	}()
	return runner
}

// Stop stops the periodic execution of the Runner.
// If the task is currently running this method will block until it is done.
func (r *Runner) Stop() {
	r.ticker.Stop()
	close(r.stop)
	<-r.loopFinished
}

// Kill is like stop but it also cancels the context of the current running method.
func (r *Runner) Kill() {
	r.ticker.Stop()
	close(r.stop)
	r.cancelF()
	<-r.loopFinished
}

// TriggerRun triggers the periodic task to run now.
// This does not impact the normal periodicity of this task.
// That means if the periodicity is 5m and you call TriggerNow() after 2 minutes,
// the next execution will be in 3 minutes.
//
// The method blocks until either the triggered run was started or the runner was stopped,
// in which case the triggered run will not be executed.
func (r *Runner) TriggerRun() {
	select {
	// Either we were stopped or we can put something in the trigger channel.
	case <-r.stop:
	case r.trigger <- struct{}{}:
	}
}

func (r *Runner) runLoop() {
	defer close(r.loopFinished)
	defer r.cancelF()
	for {
		select {
		case <-r.stop:
			return
		case <-r.ticker.Chan():
			r.onTick()
		case <-r.trigger:
			r.onTick()
		}
	}
}

func (r *Runner) onTick() {
	select {
	// Make sure that stop case is evaluated first,
	// so that when we kill and both channels are ready we always go into stop first.
	case <-r.stop:
		return
	default:
		ctx, cancelF := context.WithTimeout(r.ctx, r.timeout)
		r.task.Run(ctx)
		cancelF()
	}
}
