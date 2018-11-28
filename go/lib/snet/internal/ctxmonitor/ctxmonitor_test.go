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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

const (
	sleepForCallback = 10 * time.Millisecond
	maxWaitTime      = time.Second
)

func TestMonitor(t *testing.T) {
	Convey("Given a monitor", t, func() {
		m := NewMonitor()
		Convey("Add one context via Deadline, count is 1", func() {
			m.WithDeadline(context.Background(), time.Now().Add(time.Millisecond))
			So(m.Count(), ShouldEqual, 1)
		})
		Convey("Add one context via Timeout, count is 1", func() {
			m.WithTimeout(context.Background(), time.Second)
			So(m.Count(), ShouldEqual, 1)
		})
		Convey("Add two contexts, count is 2", func() {
			m.WithTimeout(context.Background(), time.Second)
			m.WithTimeout(context.Background(), time.Second)
			So(m.Count(), ShouldEqual, 2)
		})
		Convey("Add one context, wait for it to expire, count is 0", func() {
			ctx, cancelF := m.WithTimeout(context.Background(), time.Millisecond)
			xtest.AssertReadReturnsBefore(t, ctx.Done(), maxWaitTime)
			So(m.Count(), ShouldEqual, 0)
			cancelF()
		})
		Convey("Add one context, cancel it, count is 0", func() {
			_, cancelF := m.WithTimeout(context.Background(), time.Millisecond)
			cancelF()
			So(m.Count(), ShouldEqual, 0)
		})
		Convey("Add one context, wait for parent to expire, count is 0", func() {
			parent, cancelF := context.WithTimeout(context.Background(), time.Microsecond)
			m.WithTimeout(parent, time.Second)
			xtest.AssertReadReturnsBefore(t, parent.Done(), maxWaitTime)
			So(m.Count(), ShouldEqual, 0)
			cancelF()
		})
		Convey("Add one context, cancel parent, count is 0", func() {
			parent, parentCancelF := context.WithTimeout(context.Background(), time.Second)
			m.WithTimeout(parent, time.Second)
			parentCancelF()
			So(m.Count(), ShouldEqual, 0)
		})
		Convey("Add one context, set deadline in the past, count is 0, ctx is Done", func() {
			ctx, cancelF := m.WithTimeout(context.Background(), time.Second)
			m.SetDeadline(time.Now().Add(-time.Second))
			time.Sleep(sleepForCallback)
			SoMsg("count", m.Count(), ShouldEqual, 0)
			SoMsg("err", ctx.Err(), ShouldEqual, context.Canceled)
			cancelF()
		})
		Convey("Add one context, set deadline in the future, count is 1, ctx is not Done", func() {
			ctx, cancelF := m.WithTimeout(context.Background(), time.Second)
			m.SetDeadline(time.Now().Add(time.Second))
			time.Sleep(sleepForCallback)
			SoMsg("count", m.Count(), ShouldEqual, 1)
			SoMsg("err", ctx.Err(), ShouldBeNil)
			cancelF()
		})
		Convey("Set deadline to now, add context, ctx is immediately Done", func() {
			m.SetDeadline(time.Now())
			ctx, cancelF := m.WithTimeout(context.Background(), time.Second)
			SoMsg("count", m.Count(), ShouldEqual, 0)
			SoMsg("err", ctx.Err(), ShouldNotBeNil)
			cancelF()
		})
		Convey("Set deadline in future, add context with deadline after, ctx is not Done", func() {
			deadline := time.Now().Add(5 * time.Second)
			m.SetDeadline(deadline)
			ctx, cancelF := m.WithDeadline(context.Background(), deadline.Add(time.Second))
			SoMsg("err", ctx.Err(), ShouldBeNil)
			cancelF()
		})
	})
}

func TestDeadlineRunner(t *testing.T) {
	Convey("Given a deadline runner", t, func() {
		var runCount int64
		done := make(chan struct{})
		r := NewDeadlineRunner(
			func() {
				atomic.AddInt64(&runCount, 1)
				close(done)
			})
		Convey("If no deadline, function is not executed", func() {
			So(atomic.LoadInt64(&runCount), ShouldEqual, 0)
		})
		Convey("If deadline in the past, function is executed", func() {
			r.SetDeadline(time.Now().Add(-time.Second))
			xtest.AssertReadReturnsBefore(t, done, time.Second)
			So(atomic.LoadInt64(&runCount), ShouldEqual, 1)
		})
		Convey("If deadline in the future, function is not executed", func() {
			r.SetDeadline(time.Now().Add(time.Second))
			So(atomic.LoadInt64(&runCount), ShouldEqual, 0)
		})
		Convey("If deadline in the future and we wait, function is executed", func() {
			r.SetDeadline(time.Now().Add(10 * time.Millisecond))
			xtest.AssertReadReturnsBefore(t, done, time.Second)
			So(atomic.LoadInt64(&runCount), ShouldEqual, 1)
		})
		Convey("If deadline in the future, and then extended, the first doesn't trigger", func() {
			r.SetDeadline(time.Now().Add(10 * time.Millisecond))
			r.SetDeadline(time.Now().Add(time.Second))
			time.Sleep(20 * time.Millisecond)
			So(atomic.LoadInt64(&runCount), ShouldEqual, 0)
		})
		Convey("If deadline in the future, and is then set in past, function is executed", func() {
			r.SetDeadline(time.Now().Add(time.Second))
			r.SetDeadline(time.Now().Add(-time.Second))
			xtest.AssertReadReturnsBefore(t, done, time.Second)
			So(atomic.LoadInt64(&runCount), ShouldEqual, 1)
		})
		Convey("Setting a deadline to 0 resets it, function is not executed", func() {
			r.SetDeadline(time.Now().Add(10 * time.Millisecond))
			r.SetDeadline(time.Time{})
			time.Sleep(sleepForCallback)
			So(atomic.LoadInt64(&runCount), ShouldEqual, 0)
		})
	})
}
