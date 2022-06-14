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

package periodic_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/periodic"
)

type taskFunc func(context.Context)

func (tf taskFunc) Run(ctx context.Context) {
	tf(ctx)
}

func (tf taskFunc) Name() string {
	return "test_task"
}

func TestPeriodicExecution(t *testing.T) {
	events := metrics.NewTestCounter()
	m := periodic.Metrics{
		Events: func(s string) metrics.Counter {
			return events.With("event_type", s)
		},
		// Without additional metrics
	}

	cnt := make(chan struct{})
	fn := taskFunc(func(ctx context.Context) {
		cnt <- struct{}{}
	})
	want := 5
	p := time.Duration(want) * 20 * time.Millisecond
	r := periodic.StartWithMetrics(fn, &m, p, time.Hour)

	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		v := 0
		for {
			select {
			case <-cnt:
				v++
				if v == want {
					return
				}
			case <-time.After(5 * p):
				panic(fmt.Sprintf("timed out while waiting %d run", v))
			}
		}
	}()

	xtest.AssertReadReturnsBefore(t, done, time.Second)
	assert.WithinDurationf(t, start, time.Now(), time.Duration(want+2)*p,
		"more or less %d * periods", want+2)
	err := runWithTimeout(r.Stop, 2*time.Second)
	assert.NoError(t, err, "r.Stop() action timed out")
	// Check that  metrics work as expected
	assert.Equal(t, float64(1), metrics.CounterValue(m.Events(periodic.EventStop)))
	assert.Equal(t, float64(0), metrics.CounterValue(m.Events(periodic.EventKill)))
	assert.Equal(t, float64(0), metrics.CounterValue(m.Events(periodic.EventTrigger)))
}

func TestKillExitsLongRunningFunc(t *testing.T) {
	events := metrics.NewTestCounter()
	m := periodic.Metrics{
		Events: func(s string) metrics.Counter {
			return events.With("event_type", s)
		},
		// Without additional metrics
	}
	done, errChan := make(chan struct{}), make(chan error, 1)
	p := 10 * time.Millisecond
	fn := taskFunc(func(ctx context.Context) {
		close(done)
		select { // Simulate long work by blocking on the done channel.
		case <-ctx.Done():
			// Happy path r.Kill() cancels context
		case <-time.After(4 * p):
			t.Fatalf("goroutine took too long to finish")
		}
		errChan <- ctx.Err()
	})
	r := periodic.StartWithMetrics(fn, &m, p, time.Hour)
	xtest.AssertReadReturnsBefore(t, done, time.Second)
	err := runWithTimeout(r.Kill, time.Second)
	assert.NoError(t, err)

	select {
	case err := <-errChan:
		assert.Equal(t, context.Canceled, err, "Context should have been canceled")
	case <-time.After(5 * p):
		t.Fatalf("time out while waiting on err")
	}
	// Check that  metrics work as expected
	assert.Equal(t, float64(0), metrics.CounterValue(m.Events(periodic.EventStop)))
	assert.Equal(t, float64(1), metrics.CounterValue(m.Events(periodic.EventKill)))
	assert.Equal(t, float64(0), metrics.CounterValue(m.Events(periodic.EventTrigger)))
}

func TestTaskDoesNotRunAfterKill(t *testing.T) {
	events := metrics.NewTestCounter()
	m := periodic.Metrics{
		Events: func(s string) metrics.Counter {
			return events.With("event_type", s)
		},
		// With additional metrics
		Period:    metrics.NewTestGauge(),
		Runtime:   metrics.NewTestGauge(),
		StartTime: metrics.NewTestGauge(),
	}
	cnt := make(chan struct{}, 50)
	fn := taskFunc(func(ctx context.Context) {
		cnt <- struct{}{}
	})
	p := 10 * time.Millisecond
	startTime := time.Now()
	r := periodic.StartWithMetrics(fn, &m, p, time.Hour)

	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-cnt:
		case <-time.After(2 * p):
			panic("timed out while waiting on first run")
		}

		err := runWithTimeout(r.Kill, 2*p)
		assert.NoError(t, err)

		<-time.After(p)
	}()
	xtest.AssertReadReturnsBefore(t, done, time.Second)
	assert.Equal(t, len(cnt), 0, "No other run within a period")
	// Check that  metrics work as expected
	assert.Equal(t, float64(0), metrics.CounterValue(m.Events(periodic.EventStop)))
	assert.Equal(t, float64(1), metrics.CounterValue(m.Events(periodic.EventKill)))
	assert.Equal(t, float64(0), metrics.CounterValue(m.Events(periodic.EventTrigger)))

	assert.Equal(t, p.Seconds(), metrics.GaugeValue(m.Period))

	assert.GreaterOrEqual(t,
		float64(time.Now().UnixNano()/1e9),
		metrics.GaugeValue(m.StartTime),
	)
	assert.LessOrEqual(t,
		float64(startTime.UnixNano()/1e9),
		metrics.GaugeValue(m.StartTime),
	)

	assert.LessOrEqual(t, p.Seconds()/1e9, metrics.GaugeValue(m.Runtime))
}

func TestTriggerNow(t *testing.T) {
	events := metrics.NewTestCounter()
	m := periodic.Metrics{
		Events: func(s string) metrics.Counter {
			return events.With("event_type", s)
		},
		// With additional metrics
		Period:    metrics.NewTestGauge(),
		Runtime:   metrics.NewTestGauge(),
		StartTime: metrics.NewTestGauge(),
	}

	want := 10

	cnt := make(chan struct{}, 50)
	fn := taskFunc(func(ctx context.Context) {
		cnt <- struct{}{}
	})

	p := 10 * time.Millisecond
	startTime := time.Now()
	r := periodic.StartWithMetrics(fn, &m, p, 3*p)

	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-cnt:
		case <-time.After(2 * p):
			panic("timed out while waiting on first run")
		}
		for i := 0; i < want; i++ {
			err := runWithTimeout(r.TriggerRun, p)
			assert.NoError(t, err)
		}
	}()
	xtest.AssertReadReturnsBefore(t, done, time.Second)
	assert.GreaterOrEqual(t, len(cnt), want-1, "Must run %v times within short time", want-1)
	// Check that  metrics work as expected
	assert.Equal(t, float64(0), metrics.CounterValue(m.Events(periodic.EventStop)))
	assert.Equal(t, float64(0), metrics.CounterValue(m.Events(periodic.EventKill)))
	assert.Equal(
		t,
		float64(want),
		metrics.CounterValue(m.Events(periodic.EventTrigger)),
	)

	assert.Equal(t, p.Seconds(), metrics.GaugeValue(m.Period))

	assert.GreaterOrEqual(
		t,
		float64(time.Now().UnixNano()/1e9),
		metrics.GaugeValue(m.StartTime),
	)
	assert.LessOrEqual(
		t,
		float64(startTime.UnixNano()/1e9),
		metrics.GaugeValue(m.StartTime),
	)

	assert.LessOrEqual(t, p.Seconds()/1e9, metrics.GaugeValue(m.Runtime))
}

func runWithTimeout(f func(), t time.Duration) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
		return nil
	case <-time.After(t):
		return fmt.Errorf("timed out after %v", t)
	}
}
