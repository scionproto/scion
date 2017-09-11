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

package xtest

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestParallel(t *testing.T) {
	Convey("Test parallel goroutines", t, Parallel(func(sc *SC) {
		x := 1
		sc.SoMsg("x", x, ShouldEqual, 1)
		x += 1
		sc.SoMsg("new x", x, ShouldEqual, 2)
	}, func(sc *SC) {
		y := 1
		sc.SoMsg("y", y, ShouldEqual, 1)
		y += 1
		sc.SoMsg("new y", y, ShouldEqual, 2)
	}))
}
