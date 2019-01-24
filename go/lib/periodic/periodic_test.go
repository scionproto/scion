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
	"runtime"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

type taskFunc func(context.Context)

func (tf taskFunc) Run(ctx context.Context) {
	tf(ctx)
}

var _ (Ticker) = (*testTicker)(nil)

type testTicker struct {
	C <-chan time.Time
}

func (t *testTicker) Chan() <-chan time.Time {
	return t.C
}

func (t *testTicker) Stop() {}

func TestPeriodicExecution(t *testing.T) {
	Convey("Test periodic execution", t, func() {
		done := make(chan struct{})
		cnt := 0
		fn := taskFunc(func(ctx context.Context) {
			cnt++
			done <- struct{}{}
		})
		tickC := make(chan time.Time)
		ticker := &testTicker{C: tickC}
		r := StartPeriodicTask(fn, ticker, time.Microsecond)
		tickC <- time.Now()
		xtest.AssertReadReturnsBefore(t, done, 50*time.Millisecond)
		tickC <- time.Now()
		xtest.AssertReadReturnsBefore(t, done, 50*time.Millisecond)
		tickC <- time.Now()
		xtest.AssertReadReturnsBefore(t, done, 50*time.Millisecond)
		r.Stop()
		SoMsg("Must have executed 3 times", cnt, ShouldEqual, 3)
	})
}

func TestKillExitsLongRunningFunc(t *testing.T) {
	Convey("Test kill cancels the context of the run function", t, func() {
		errChan := make(chan error, 1)
		fn := taskFunc(func(ctx context.Context) {
			// Simulate long work by blocking on the done channel.
			xtest.AssertReadReturnsBefore(t, ctx.Done(), time.Second)
			errChan <- ctx.Err()
		})
		tickC := make(chan time.Time)
		ticker := &testTicker{C: tickC}
		r := StartPeriodicTask(fn, ticker, time.Second)
		// trigger the periodic method.
		tickC <- time.Now()
		r.Kill()
		var err error
		select {
		case err = <-errChan:
		case <-time.After(time.Second):
			t.Fatalf("time out while waiting on err")
		}
		SoMsg("Context should have been canceled", err, ShouldEqual, context.Canceled)
	})
}

func TestTaskDoesntRunAfterKill(t *testing.T) {
	Convey("Test task doesn't run after the periodic runner was killed.", t, func() {
		fn := taskFunc(func(ctx context.Context) {
			t.Fatalf("Should not have executed")
		})
		tickC := make(chan time.Time)
		ticker := &testTicker{C: tickC}
		// Try to make sure tick channel is full.
		go func() {
			tickC <- time.Now()
		}()
		runtime.Gosched()
		// Now start the task and immediately kill it.
		r := StartPeriodicTask(fn, ticker, time.Second)
		r.Kill()
	})
}

func TestTriggerNow(t *testing.T) {
	Convey("TestTriggerNow", t, func() {
		done := make(chan struct{})
		cnt := 0
		fn := taskFunc(func(ctx context.Context) {
			cnt++
			done <- struct{}{}
		})
		tickC := make(chan time.Time)
		ticker := &testTicker{C: tickC}
		r := StartPeriodicTask(fn, ticker, time.Microsecond)
		r.TriggerRun()
		xtest.AssertReadReturnsBefore(t, done, 50*time.Millisecond)
		tickC <- time.Now()
		xtest.AssertReadReturnsBefore(t, done, 50*time.Millisecond)
		r.TriggerRun()
		xtest.AssertReadReturnsBefore(t, done, 50*time.Millisecond)
		r.Stop()
		// check that a trigger after stop doesn't do anything.
		r.TriggerRun()
		SoMsg("Must have executed 3 times", cnt, ShouldEqual, 3)
	})
}
