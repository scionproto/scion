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

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/pkg/log"
	emetrics "github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/private/periodic/internal/metrics"
)

// A Task that has to be periodically executed.
type Task interface {
	// Run executes the task once, it should return within the context's timeout.
	Run(context.Context)
	// Name returns the task's name for use in metrics and tracing. Each
	// successive call should return the same value as the first call. Names
	// must only contain [a-z] and _ characters.
	Name() string
}

const (
	// EventStop indicates a stop event took place.
	EventStop = "stop"
	// EventKill indicates a kill event took place.
	EventKill = "kill"
	// EventTrigger indicates a trigger event took place.
	EventTrigger = "triggered"
)

// Metrics contins the relavant metrics for the task in the same Runner.
type Metrics struct {
	// Events tracks the amount of occurrences of events defined above.
	Events func(string) emetrics.Counter
	// Period is a Gauge describing the current period.
	Period emetrics.Gauge
	// Runtime tracks how long the task has been running.
	Runtime emetrics.Gauge
	// StartTime is a timestamp of when the task was started.
	StartTime emetrics.Gauge
}

func (m Metrics) SetStartTimestamp(t time.Time) {
	if m.StartTime != nil {
		m.StartTime.Set(float64(t.UnixNano() / 1e9))
	}
}

func (m Metrics) SetPeriod(d time.Duration) {
	if m.Period != nil {
		m.Period.Set(d.Seconds())
	}
}

func (m Metrics) SetRuntime(d time.Duration) {
	if m.Runtime != nil {
		m.Runtime.Add(float64(d) / 1e9)
	}
}

func (m Metrics) Event(s string) {
	if m.Events != nil {
		m.Events(s).Add(1)
	}
}

// Func implements the Task interface.
type Func struct {
	// Task is the function that is executed on Run.
	Task func(context.Context)
	// TaskName is the name returned by Name,
	TaskName string
}

// Run runs the task function.
func (f Func) Run(ctx context.Context) {
	f.Task(ctx)
}

// Name returns the task name.
func (f Func) Name() string {
	return f.TaskName
}

// Runner runs a task periodically.
type Runner struct {
	task         Task
	ticker       *time.Ticker
	timeout      time.Duration
	stop         chan struct{}
	loopFinished chan struct{}
	ctx          context.Context
	cancelF      context.CancelFunc
	trigger      chan struct{}
	metric       Metrics
}

// Stop stops the periodic execution of the Runner.
// If the task is currently running this method will block until it is done.
func (r *Runner) Stop() {
	r.ticker.Stop()
	close(r.stop)
	<-r.loopFinished
	r.metric.Event(EventStop)
}

// Kill is like stop but it also cancels the context of the current running method.
func (r *Runner) Kill() {
	if r == nil {
		return
	}
	r.ticker.Stop()
	close(r.stop)
	r.cancelF()
	<-r.loopFinished
	r.metric.Event(EventKill)
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
	r.metric.Event(EventTrigger)
}

func (r *Runner) runLoop() {
	defer close(r.loopFinished)
	defer r.cancelF()
	for {
		select {
		case <-r.stop:
			return
		case <-r.ticker.C:
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
		span, ctx := opentracing.StartSpanFromContext(ctx, "periodic."+r.task.Name())
		defer span.Finish()
		start := time.Now()
		r.task.Run(ctx)
		r.metric.SetRuntime(time.Since(start))
		cancelF()
	}
}

// Start creates and starts a new Runner to run the given task peridiocally.
// The timeout is used for the context timeout of the task. The timeout can be
// larger than the periodicity of the task. That means if a tasks takes a long
// time it will be immediately retriggered.
func Start(task Task, period, timeout time.Duration) *Runner {
	genMetric := metrics.NewMetric(task.Name())
	metric := Metrics{
		Events:    genMetric.GetEvents(),
		Period:    genMetric.GetPeriod(),
		Runtime:   genMetric.GetRuntime(),
		StartTime: genMetric.GetTimestamp(),
	}
	return StartWithMetric(task, metric, period, timeout)
}

// StartWithMetric is identical to Start but allows the caller to
// specify the metric or no metric at all to be used.
func StartWithMetric(task Task, metric Metrics, period, timeout time.Duration) *Runner {
	ctx, cancelF := context.WithCancel(context.Background())
	logger := log.New("debug_id", log.NewDebugID())
	ctx = log.CtxWith(ctx, logger)
	r := &Runner{
		task:         task,
		ticker:       time.NewTicker(period),
		timeout:      timeout,
		stop:         make(chan struct{}),
		loopFinished: make(chan struct{}),
		ctx:          ctx,
		cancelF:      cancelF,
		trigger:      make(chan struct{}),
		metric:       metric,
	}
	logger.Info("Starting periodic task", "task", task.Name())
	if r.metric.Period != nil {
		r.metric.Period.Set(period.Seconds())
	}
	if r.metric.StartTime != nil {
		r.metric.SetStartTimestamp(time.Now())
	}
	go func() {
		defer log.HandlePanic()
		r.runLoop()
	}()
	return r
}
