// Copyright 2017 ETH Zurich
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

// Package xtest implements common functionality for unit tests. This includes
// support for assertions in multiple goroutines to Goconvey, and temporary
// test file/folder helpers.
//
// Parallel goconvey blocks cannot contain other goconvey blocks.
//
// Example:
//
//  func TestParallel(t *testing.T) {
//    Convey("Test parallel goroutines", t, Parallel(func(sc *SC) {
//      x := 1
//      sc.SoMsg("x", x, ShouldEqual, 1)
//    }, func(sc *SC) {
//      y := 1
//      sc.SoMsg("y", y, ShouldEqual, 1)
//    }))
//  }
//
// Note that inside parallel blocks, Convey methods should be explicitly
// invoked on the local convey object (e.g., sc).
package xtest

import (
	"sync"

	. "github.com/smartystreets/goconvey/convey"
)

type SC struct {
	C
	sync.WaitGroup
	sync.Mutex
}

func (c *SC) Convey(items ...interface{}) {
	panic("Convey in SyncConvey Context not supported")
}

func (c *SC) So(actual interface{},
	assert func(actual interface{}, expected ...interface{}) string, expected ...interface{}) {
	c.Lock()
	defer c.Unlock()
	c.C.So(actual, assert, expected)
}

func (c *SC) SoMsg(msg string, actual interface{},
	assert func(actual interface{}, expected ...interface{}) string, expected ...interface{}) {
	c.Lock()
	defer c.Unlock()
	c.C.SoMsg(msg, actual, assert, expected...)
}

func (c *SC) Recover() {
	if r := recover(); r != nil {
		// Silently discard failure halts
		if rString, ok := r.(string); ok && rString == "___FAILURE_HALT___" {
			return
		}
		panic(r)
	}
}

func Parallel(f, g func(sc *SC)) func(c C) {
	return func(c C) {
		sc := &SC{C: c}
		sc.Add(1)
		go func() {
			// If g panics, first recover from the panic. Afterwards (or if g
			// finishes normally), announce that g finished.
			defer sc.Done()
			defer sc.Recover()
			g(sc)
		}()
		// If f panics, first recover from the panic. Afterwards (or if f
		// finishes normally), wait for g to finish.
		defer sc.Wait()
		defer sc.Recover()
		f(sc)
	}
}

// SoMsgError wraps nil/non-nil error Goconvey assertions into a single yes/no
// error check. The assertions pass if err is nil and shouldBeError is false,
// or if err is non-nil and shouldBeError is true. In the latter case, no
// equality check is performed.
func SoMsgError(msg string, err error, shouldBeError bool) {
	if shouldBeError == true {
		SoMsg(msg, err, ShouldNotBeNil)
	} else {
		SoMsg(msg, err, ShouldBeNil)
	}
}
