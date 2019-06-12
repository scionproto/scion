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

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/mock_xtest"
	"github.com/scionproto/scion/go/proto"
)

type updateTestFunc func(*topology.Topo) (*topology.Topo, bool, error)

func setStaticTestFunc(s *state) updateTestFunc {
	return func(t *topology.Topo) (*topology.Topo, bool, error) {
		return s.setStatic(t, false)
	}
}

func TestInit(t *testing.T) {
	Convey("Initializing itopo twice should panic", t, func() {
		SoMsg("first", func() { Init("", 0, Callbacks{}) }, ShouldNotPanic)
		SoMsg("second", func() { Init("", 0, Callbacks{}) }, ShouldPanic)
	})
}

func TestStateSetStatic(t *testing.T) {
	mctrl := gomock.NewController(&xtest.PanickingReporter{T: t})
	defer mctrl.Finish()
	Convey("When state is initialized with no specific element", t, func() {
		clbks := newMockClbks(mctrl)
		s := newState("", proto.ServiceType_unset, clbks.Clbks())
		s.topo.static = loadTopo(fn, t)
		// Set dynamic such that drop dynamic might possibly be called.
		s.topo.dynamic = loadTopo(fn, t)
		topo := loadTopo(fn, t)
		Convey("Calling with modified topo should succeed", func() {
			var wg xtest.Waiter
			wg.Add(1)
			ifinfo := topo.IFInfoMap[1]
			ifinfo.MTU = 42
			topo.IFInfoMap[1] = ifinfo
			clbks.update.EXPECT().Call().Do(wg.Done)
			newTopo, updated, err := s.setStatic(topo, true)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeTrue)
			SoMsg("topo static", topo, ShouldEqual, s.topo.static)
			SoMsg("topo dynamic", newTopo, ShouldEqual, s.topo.dynamic)
			wg.WaitWithTimeout(time.Second)
		})
		testNilTopo(setStaticTestFunc(s), t)
		testNoModified(setStaticTestFunc(s), s.topo.static, clbks, true, t)
	})
	Convey("When itopo is initialized with a service element", t, func() {
		clbks := newMockClbks(mctrl)
		id := "cs1-ff00:0:311-1"
		s := newState(id, proto.ServiceType_cs, clbks.Clbks())
		s.topo.static = loadTopo(fn, t)
		// Set dynamic such that drop dynamic might possibly be called.
		s.topo.dynamic = loadTopo(fn, t)
		topo := loadTopo(fn, t)
		Convey("Modification without touching the element's entry should be allowed", func() {
			var wg xtest.Waiter
			wg.Add(1)
			// Modify border router
			ifinfo := topo.IFInfoMap[1]
			ifinfo.MTU = 42
			topo.IFInfoMap[1] = ifinfo
			// modify other cs
			cs := topo.CS["cs1-ff00:0:311-2"]
			cs.Overlay = overlay.IPv6
			topo.CS["cs1-ff00:0:311-2"] = cs
			clbks.update.EXPECT().Call().Do(wg.Done)
			newTopo, updated, err := s.setStatic(topo, true)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeTrue)
			SoMsg("topo static", topo, ShouldEqual, s.topo.static)
			SoMsg("topo dynamic", newTopo, ShouldEqual, s.topo.dynamic)
			wg.WaitWithTimeout(time.Second)
		})
		Convey("Modifying the element's entry should not be allowed", func() {
			cs := topo.CS[id]
			cs.Overlay = overlay.IPv6
			topo.CS[id] = cs
			_, updated, err := s.setStatic(topo, true)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("updated", updated, ShouldBeFalse)
			SoMsg("topo static", topo, ShouldNotEqual, s.topo.static)
		})
		testNilTopo(setStaticTestFunc(s), t)
		testNoModified(setStaticTestFunc(s), s.topo.static, clbks, true, t)
	})
	Convey("When itopo is initialized with a border router", t, func() {
		clbks := newMockClbks(mctrl)
		id := "br1-ff00:0:311-1"
		s := newState(id, proto.ServiceType_br, clbks.Clbks())
		s.topo.static = loadTopo(fn, t)
		// Set dynamic such that drop dynamic might possibly be called.
		s.topo.dynamic = loadTopo(fn, t)
		topo := loadTopo(fn, t)
		Convey("Modification without touching the br's entry should be allowed", func() {
			var wg xtest.Waiter
			wg.Add(1)
			// Modify border router
			ifinfo := topo.IFInfoMap[2]
			ifinfo.MTU = 42
			topo.IFInfoMap[2] = ifinfo
			// modify other cs
			cs := topo.CS["cs1-ff00:0:311-2"]
			cs.Overlay = overlay.IPv6
			topo.CS["cs1-ff00:0:311-2"] = cs
			Convey("If semi-mutation is allowed", func() {
				clbks.update.EXPECT().Call().Do(wg.Done)
				newTopo, updated, err := s.setStatic(topo, true)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("updated", updated, ShouldBeTrue)
				SoMsg("topo static", topo, ShouldEqual, s.topo.static)
				SoMsg("topo dynamic", newTopo, ShouldEqual, s.topo.dynamic)
				wg.WaitWithTimeout(time.Second)
			})
			Convey("If semi-mutation is not allowed", func() {
				clbks.update.EXPECT().Call().Do(wg.Done)
				newTopo, updated, err := s.setStatic(topo, false)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("updated", updated, ShouldBeTrue)
				SoMsg("topo static", topo, ShouldEqual, s.topo.static)
				SoMsg("topo dynamic", newTopo, ShouldEqual, s.topo.dynamic)
				wg.WaitWithTimeout(time.Second)
			})
		})
		Convey("Modifying the internal address is not allowed", func() {
			brInfo := topo.BR[id]
			brInfo.InternalAddrs.Overlay = overlay.IPv6
			topo.BR[id] = brInfo
			Convey("If semi-mutation is allowed", func() {
				_, updated, err := s.setStatic(topo, true)
				SoMsg("err", err, ShouldNotBeNil)
				SoMsg("updated", updated, ShouldBeFalse)
				SoMsg("topo static", topo, ShouldNotEqual, s.topo.static)
			})
			Convey("If semi-mutation is not allowed", func() {
				_, updated, err := s.setStatic(topo, false)
				SoMsg("err", err, ShouldNotBeNil)
				SoMsg("updated", updated, ShouldBeFalse)
				SoMsg("topo static", topo, ShouldNotEqual, s.topo.static)
			})
		})
		Convey("Modifying an interface is only allowed if semi-mutations are allowed", func() {
			ifinfo := topo.IFInfoMap[1]
			ifinfo.MTU = 42
			topo.IFInfoMap[1] = ifinfo
			Convey("Succeed, if semi-mutation is allowed", func() {
				var wg xtest.Waiter
				wg.Add(2)
				clbks.update.EXPECT().Call().Do(wg.Done)
				clbks.drop.EXPECT().Call().Do(wg.Done)
				newTopo, updated, err := s.setStatic(topo, true)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("updated", updated, ShouldBeTrue)
				SoMsg("topo", newTopo, ShouldEqual, topo)
				wg.WaitWithTimeout(time.Second)
			})
			Convey("Fail, if semi-mutation is not allowed", func() {
				_, updated, err := s.setStatic(topo, false)
				SoMsg("err", err, ShouldNotBeNil)
				SoMsg("updated", updated, ShouldBeFalse)
				SoMsg("topo static", topo, ShouldNotEqual, s.topo.static)
			})
		})
		testNilTopo(setStaticTestFunc(s), t)
		testNoModified(setStaticTestFunc(s), s.topo.static, clbks, true, t)
	})
}

func TestStateSetDynamic(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	Convey("When state is initialized with no specific element", t, func() {
		clbks := newMockClbks(mctrl)
		s := newState("", proto.ServiceType_unset, clbks.Clbks())
		s.topo.static = loadTopo(fn, t)
		// Set dynamic such that drop dynamic might possibly be called.
		s.topo.dynamic = loadTopo(fn, t)
		topo := loadTopo(fn, t)
		topo.Timestamp = time.Now()
		Convey("Calling with modified topo should succeed", func() {
			ifinfo := topo.IFInfoMap[1]
			ifinfo.MTU = 42
			topo.IFInfoMap[1] = ifinfo
			newTopo, updated, err := s.setDynamic(topo)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeTrue)
			SoMsg("topo", newTopo, ShouldEqual, topo)
		})
		testNilTopo(s.setDynamic, t)
		testNoModified(s.setDynamic, s.topo.dynamic, clbks, false, t)
	})
	Convey("When itopo is initialized with a service element", t, func() {
		clbks := newMockClbks(mctrl)
		id := "cs1-ff00:0:311-1"
		s := newState(id, proto.ServiceType_cs, clbks.Clbks())
		s.topo.static = loadTopo(fn, t)
		// Set dynamic such that drop dynamic might possibly be called.
		s.topo.dynamic = loadTopo(fn, t)
		topo := loadTopo(fn, t)
		topo.Timestamp = time.Now()
		Convey("Modification without touching the element's entry should be allowed", func() {
			// Modify border router
			ifinfo := topo.IFInfoMap[1]
			ifinfo.MTU = 42
			topo.IFInfoMap[1] = ifinfo
			// modify other cs
			cs := topo.CS["cs1-ff00:0:311-2"]
			cs.Overlay = overlay.IPv6
			topo.CS["cs1-ff00:0:311-2"] = cs
			newTopo, updated, err := s.setDynamic(topo)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeTrue)
			SoMsg("topo", newTopo, ShouldEqual, topo)
		})
		Convey("Modifying the element's entry should not be allowed", func() {
			cs := topo.CS[id]
			cs.Overlay = overlay.IPv6
			topo.CS[id] = cs
			_, updated, err := s.setDynamic(topo)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("updated", updated, ShouldBeFalse)
		})
		testNilTopo(s.setDynamic, t)
		testNoModified(s.setDynamic, s.topo.dynamic, clbks, false, t)
	})
	Convey("When itopo is initialized with a border router", t, func() {
		clbks := newMockClbks(mctrl)
		id := "br1-ff00:0:311-1"
		s := newState(id, proto.ServiceType_br, clbks.Clbks())
		s.topo.static = loadTopo(fn, t)
		// Set dynamic such that drop dynamic might possibly be called.
		s.topo.dynamic = loadTopo(fn, t)
		topo := loadTopo(fn, t)
		topo.Timestamp = time.Now()
		Convey("Modification without touching the br's entry should be allowed", func() {
			// Modify border router
			ifinfo := topo.IFInfoMap[2]
			ifinfo.MTU = 42
			topo.IFInfoMap[2] = ifinfo
			// modify other cs
			cs := topo.CS["cs1-ff00:0:311-2"]
			cs.Overlay = overlay.IPv6
			topo.CS["cs1-ff00:0:311-2"] = cs
			newTopo, updated, err := s.setDynamic(topo)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeTrue)
			SoMsg("topo", newTopo, ShouldEqual, topo)
		})
		Convey("Modifying the internal address is not allowed", func() {
			brInfo := topo.BR[id]
			brInfo.InternalAddrs.Overlay = overlay.IPv6
			topo.BR[id] = brInfo
			_, updated, err := s.setDynamic(topo)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("updated", updated, ShouldBeFalse)
		})
		Convey("Modifying an interfaces is not allowed", func() {
			ifinfo := topo.IFInfoMap[1]
			ifinfo.MTU = 42
			topo.IFInfoMap[1] = ifinfo
			_, updated, err := s.setDynamic(topo)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("updated", updated, ShouldBeFalse)
		})
		testNilTopo(s.setDynamic, t)
		testNoModified(s.setDynamic, s.topo.dynamic, clbks, false, t)
	})
}

func testNilTopo(update updateTestFunc, t *testing.T) {
	Convey("Calling with nil topo should fail", func() {
		_, updated, err := update(nil)
		SoMsg("err", err, ShouldNotBeNil)
		SoMsg("updated", updated, ShouldBeFalse)
	})
}

func testNoModified(update updateTestFunc, prevTopo *topology.Topo,
	clbks *mockClbks, updateCalled bool, t *testing.T) {

	t.Helper()
	Convey("Calling with non-modified topo should succeed", func() {
		topo := loadTopo(fn, t)
		topo.Timestamp = prevTopo.Timestamp
		Convey("No update without time changes", func() {
			_, updated, err := update(topo)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeFalse)
		})
		Convey("No update if expires earlier", func() {
			topo.TTL -= 2 * time.Second
			_, updated, err := update(topo)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeFalse)
		})
		Convey("Update if expires later", func() {
			var wg xtest.Waiter
			topo.TTL += 2 * time.Second
			if updateCalled {
				wg.Add(1)
				clbks.update.EXPECT().Call().Do(wg.Done)
			}
			_, updated, err := update(topo)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("updated", updated, ShouldBeTrue)
			wg.WaitWithTimeout(time.Second)
		})
	})
}

type mockClbks struct {
	clean  *mock_xtest.MockCallback
	drop   *mock_xtest.MockCallback
	update *mock_xtest.MockCallback
}

func newMockClbks(mctrl *gomock.Controller) *mockClbks {
	return &mockClbks{
		clean:  mock_xtest.NewMockCallback(mctrl),
		drop:   mock_xtest.NewMockCallback(mctrl),
		update: mock_xtest.NewMockCallback(mctrl),
	}
}

func (clbks *mockClbks) Clbks() Callbacks {
	return Callbacks{
		CleanDynamic: clbks.clean.Call,
		DropDynamic:  clbks.drop.Call,
		UpdateStatic: clbks.update.Call,
	}
}
