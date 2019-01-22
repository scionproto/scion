// Copyright 2019 Anapaya Systems
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

package itopo

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSetStatic(t *testing.T) {
	Convey("When itopo is initialized with no specific element", t, func() {
		staticTopo = nil
		called := clbkCalled{}
		err := Init(loadTopo(fn, t), called.clbks())
		SoMsg("err", err, ShouldBeNil)
		dynamicTopo = staticTopo
		topo := loadTopo(fn, t)
		Convey("Calling with modified topo should succeed", func() {
			ifinfo := topo.IFInfoMap[1]
			ifinfo.MTU = 42
			topo.IFInfoMap[1] = ifinfo
			newTopo, updated, err := SetStatic(topo, true)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeTrue)
			SoMsg("topo", newTopo, ShouldEqual, topo)
			called.check(false, false, true)
		})
		testNilTopo(&called, t)
		testNoModified(&called, t)
	})
}

func testNilTopo(called *clbkCalled, t *testing.T) {
	Convey("Calling with nil topo should fail", func() {
		_, updated, err := SetStatic(nil, true)
		SoMsg("err", err, ShouldNotBeNil)
		SoMsg("updated", updated, ShouldBeFalse)
		called.check(false, false, false)
	})
}

func testNoModified(called *clbkCalled, t *testing.T) {
	t.Helper()
	Convey("Calling with non-modified topo should succeed", func() {
		topo := loadTopo(fn, t)
		Convey("No update without time changes", func() {
			prevTopo := staticTopo
			newTopo, updated, err := SetStatic(topo, true)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeFalse)
			SoMsg("topo", newTopo, ShouldEqual, prevTopo)
			called.check(false, false, false)
		})
		Convey("No update if expires earlier", func() {
			topo.Timestamp = topo.Timestamp.Add(time.Second)
			topo.TTL -= 2 * time.Second
			prevTopo := staticTopo
			newTopo, updated, err := SetStatic(topo, true)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeFalse)
			SoMsg("topo", newTopo, ShouldEqual, prevTopo)
			called.check(false, false, false)
		})
		Convey("Update if expires later", func() {
			topo.Timestamp = topo.Timestamp.Add(time.Second)
			newTopo, updated, err := SetStatic(topo, true)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeTrue)
			SoMsg("topo", newTopo, ShouldEqual, topo)
			called.check(false, false, true)
		})
	})
}

type clbkCalled struct {
	clean  bool
	drop   bool
	update bool
}

func (c *clbkCalled) check(clean, drop, update bool) {
	// Wait for callbacks to be executed
	time.Sleep(10 * time.Millisecond)
	SoMsg("clbk clean", c.clean, ShouldEqual, clean)
	SoMsg("clbk drop", c.drop, ShouldEqual, drop)
	SoMsg("clbk update", c.update, ShouldEqual, update)
}

func (c *clbkCalled) clbks() *Clbks {
	return &Clbks{
		CleanDynamic: func() { c.clean = true },
		DropDynamic:  func() { c.drop = true },
		UpdateStatic: func() { c.update = true },
	}
}
