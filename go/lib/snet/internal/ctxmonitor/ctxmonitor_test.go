// Copyright 2018 ETH Zurich
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

package ctxmonitor

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/xtest"
)

const (
	sleepForCallback = 10 * time.Millisecond
	maxWaitTime      = time.Second
)

func TestMonitor(t *testing.T) {
	t.Log("Given a monitor")
	//m := NewMonitor()
	t.Run("Add one context via Deadline, count is 1", func(t *testing.T) {
		m := NewMonitor()
		m.WithDeadline(context.Background(), time.Now().Add(time.Millisecond))
		assert.Equal(t, m.Count(), 1)
	})
	t.Run("Add one context via Timeout, count is 1", func(t *testing.T) {
		m := NewMonitor()
		m.WithTimeout(context.Background(), time.Second)
		assert.Equal(t, m.Count(), 1)
	})
	t.Run("Add two contexts, count is 2", func(t *testing.T) {
		m := NewMonitor()
		m.WithTimeout(context.Background(), time.Second)
		m.WithTimeout(context.Background(), time.Second)
		assert.Equal(t, m.Count(), 2)
	})
	t.Run("Add one context, wait for it to expire, count is 0", func(t *testing.T) {
		m := NewMonitor()
		ctx, cancelF := m.WithTimeout(context.Background(), time.Millisecond)
		xtest.AssertReadReturnsBefore(t, ctx.Done(), maxWaitTime)
		assert.Equal(t, m.Count(), 0)
		cancelF()
	})
	t.Run("Add one context, cancel it, count is 0", func(t *testing.T) {
		m := NewMonitor()
		_, cancelF := m.WithTimeout(context.Background(), time.Millisecond)
		cancelF()
		assert.Equal(t, m.Count(), 0)
	})
	t.Run("Add one context, wait for parent to expire, count is 0", func(t *testing.T) {
		m := NewMonitor()
		parent, cancelF := context.WithTimeout(context.Background(), time.Microsecond)
		m.WithTimeout(parent, time.Second)
		xtest.AssertReadReturnsBefore(t, parent.Done(), maxWaitTime)
		assert.Equal(t, m.Count(), 0)
		cancelF()
	})
	t.Run("Add one context, cancel parent, count is 0", func(t *testing.T) {
		m := NewMonitor()
		parent, parentCancelF := context.WithTimeout(context.Background(), time.Second)
		m.WithTimeout(parent, time.Second)
		parentCancelF()
		assert.Equal(t, m.Count(), 0)
	})
	t.Run("Add one context, set deadline in the past, count is 0, ctx is Done", func(t *testing.T) {
		m := NewMonitor()
		ctx, cancelF := m.WithTimeout(context.Background(), time.Second)
		m.SetDeadline(time.Now().Add(-time.Second))
		time.Sleep(sleepForCallback)
		assert.Equal(t, m.Count(), 0, "count")
		assert.Equal(t, ctx.Err(), context.Canceled, "err")
		cancelF()
	})
	t.Run("Add one context, set deadline in the future, count is 1, ctx is not Done",
		func(t *testing.T) {
			m := NewMonitor()
			ctx, cancelF := m.WithTimeout(context.Background(), time.Second)
			m.SetDeadline(time.Now().Add(time.Second))
			time.Sleep(sleepForCallback)
			assert.Equal(t, m.Count(), 1, "count")
			assert.NoError(t, ctx.Err())
			cancelF()
		})
	t.Run("Set deadline to now, add context, ctx is immediately Done", func(t *testing.T) {
		m := NewMonitor()
		m.SetDeadline(time.Now())
		ctx, cancelF := m.WithTimeout(context.Background(), time.Second)
		assert.Equal(t, m.Count(), 0, "count")
		assert.Error(t, ctx.Err())
		cancelF()
	})
	t.Run("Set deadline in future, add context with deadline after, ctx is not Done",
		func(t *testing.T) {
			m := NewMonitor()
			deadline := time.Now().Add(5 * time.Second)
			m.SetDeadline(deadline)
			ctx, cancelF := m.WithDeadline(context.Background(), deadline.Add(time.Second))
			assert.NoError(t, ctx.Err())
			cancelF()
		})
}

func TestDeadlineRunner(t *testing.T) {
	t.Log("Given a deadline runner")
	t.Run("If no deadline, function is not executed", func(t *testing.T) {
		var runCount int64
		assert.Equal(t, atomic.LoadInt64(&runCount), int64(0))
	})
	t.Run("If deadline in the past, function is executed", func(t *testing.T) {
		var runCount int64
		done := make(chan struct{})
		r := NewDeadlineRunner(
			func() {
				atomic.AddInt64(&runCount, 1)
				close(done)
			})

		r.SetDeadline(time.Now().Add(-time.Second))
		xtest.AssertReadReturnsBefore(t, done, time.Second)
		assert.Equal(t, atomic.LoadInt64(&runCount), int64(1))
	})
	t.Run("If deadline in the future, function is not executed", func(t *testing.T) {
		var runCount int64
		done := make(chan struct{})
		r := NewDeadlineRunner(
			func() {
				atomic.AddInt64(&runCount, 1)
				close(done)
			})

		r.SetDeadline(time.Now().Add(time.Second))
		assert.Equal(t, atomic.LoadInt64(&runCount), int64(0))
	})
	t.Run("If deadline in the future and we wait, function is executed", func(t *testing.T) {
		var runCount int64
		done := make(chan struct{})
		r := NewDeadlineRunner(
			func() {
				atomic.AddInt64(&runCount, 1)
				close(done)
			})

		r.SetDeadline(time.Now().Add(10 * time.Millisecond))
		xtest.AssertReadReturnsBefore(t, done, time.Second)
		assert.Equal(t, atomic.LoadInt64(&runCount), int64(1))
	})
	t.Run("If deadline in the future, and then extended, the first doesn't trigger",
		func(t *testing.T) {
			var runCount int64
			done := make(chan struct{})
			r := NewDeadlineRunner(
				func() {
					atomic.AddInt64(&runCount, 1)
					close(done)
				})

			r.SetDeadline(time.Now().Add(10 * time.Millisecond))
			r.SetDeadline(time.Now().Add(time.Second))
			time.Sleep(20 * time.Millisecond)
			assert.Equal(t, atomic.LoadInt64(&runCount), int64(0))
		})
	t.Run("If deadline in the future, and is then set in past, function is executed",
		func(t *testing.T) {
			var runCount int64
			done := make(chan struct{})
			r := NewDeadlineRunner(
				func() {
					atomic.AddInt64(&runCount, 1)
					close(done)
				})

			r.SetDeadline(time.Now().Add(time.Second))
			r.SetDeadline(time.Now().Add(-time.Second))
			xtest.AssertReadReturnsBefore(t, done, time.Second)
			assert.Equal(t, atomic.LoadInt64(&runCount), int64(1))
		})
	t.Run("Setting a deadline to 0 resets it, function is not executed", func(t *testing.T) {
		var runCount int64
		done := make(chan struct{})
		r := NewDeadlineRunner(
			func() {
				atomic.AddInt64(&runCount, 1)
				close(done)
			})
		r.SetDeadline(time.Now().Add(10 * time.Millisecond))
		r.SetDeadline(time.Time{})
		time.Sleep(sleepForCallback)
		assert.Equal(t, atomic.LoadInt64(&runCount), int64(0))
	})
}
