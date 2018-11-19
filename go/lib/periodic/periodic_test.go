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
		cnt := 0
		fn := taskFunc(func(ctx context.Context) {
			cnt++
		})
		tickC := make(chan time.Time)
		ticker := &testTicker{C: tickC}
		r := StartPeriodicTask(fn, ticker, time.Microsecond)
		tickC <- time.Now()
		tickC <- time.Now()
		tickC <- time.Now()
		r.Stop()
		SoMsg("Must have executed 3 times", cnt, ShouldEqual, 3)
	})
}

func TestKill(t *testing.T) {
	Convey("Test kill works", t, func() {
		done := make(chan struct{})
		var err error
		fn := taskFunc(func(ctx context.Context) {
			<-ctx.Done()
			err = ctx.Err()
			close(done)
		})
		tickC := make(chan time.Time, 2)
		ticker := &testTicker{C: tickC}
		r := StartPeriodicTask(fn, ticker, time.Second)
		tickC <- time.Now()
		// Fill the channel to check that stop is always selected
		// and run is never called after kill.
		tickC <- time.Now()
		// Make sure the go routine can start
		runtime.Gosched()
		r.Kill()
		<-done
		SoMsg("Context should have been canceled", err, ShouldEqual, context.Canceled)
	})
}
