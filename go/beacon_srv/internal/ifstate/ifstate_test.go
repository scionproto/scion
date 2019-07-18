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

package ifstate

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/topology"
)

func TestInterfacesUpdate(t *testing.T) {
	Convey("Given an interface infos map with existing entries", t, func() {
		intfs := testInterfaces()
		Convey("The update retains the state of the interface", func() {
			topoMap := topology.IfInfoMap{
				1: {BRName: "BR-1-new"},
				2: {BRName: "BR-2-new"},
			}
			intfs.Update(topoMap)
			// The topo info should come from the updated map.
			SoMsg("Name 1", intfs.Get(1).TopoInfo().BRName, ShouldEqual, "BR-1-new")
			SoMsg("Name 2", intfs.Get(2).TopoInfo().BRName, ShouldEqual, "BR-2-new")
			// The remote ifid should be kept
			SoMsg("Ifid 1", intfs.Get(1).TopoInfo().RemoteIFID, ShouldEqual, 11)
			SoMsg("Ifid 2", intfs.Get(2).TopoInfo().RemoteIFID, ShouldEqual, 22)
			// The state should be kept
			SoMsg("State 1", intfs.Get(1).State(), ShouldEqual, Active)
			SoMsg("State 2", intfs.Get(2).State(), ShouldEqual, Revoked)
		})
		Convey("The update adds new interfaces and removes missing", func() {
			topoMap := topology.IfInfoMap{
				3: {BRName: "BR-3-new"},
			}
			intfs.Update(topoMap)
			SoMsg("Gone 1", intfs.Get(1), ShouldBeNil)
			SoMsg("Gone 2", intfs.Get(2), ShouldBeNil)
			SoMsg("Name 3", intfs.Get(3).TopoInfo().BRName, ShouldEqual, "BR-3-new")
		})
	})
}

func TestInterfacesReset(t *testing.T) {
	Convey("Given an interface infos map with existing entries", t, func() {
		intfs := testInterfaces()
		Convey("Reset resets the info state", func() {
			intfs.Reset()
			// The topo info should remain.
			SoMsg("Name 1", intfs.Get(1).TopoInfo().BRName, ShouldEqual, "BR-1")
			SoMsg("Name 2", intfs.Get(2).TopoInfo().BRName, ShouldEqual, "BR-2")
			SoMsg("Ifid 1", intfs.Get(1).TopoInfo().RemoteIFID, ShouldEqual, 11)
			SoMsg("Ifid 2", intfs.Get(2).TopoInfo().RemoteIFID, ShouldEqual, 22)
			// The state and revocations should be reset.
			SoMsg("State 1", intfs.Get(1).State(), ShouldEqual, Inactive)
			SoMsg("State 2", intfs.Get(2).State(), ShouldEqual, Inactive)
			SoMsg("Revocation 1", intfs.Get(1).Revocation(), ShouldBeNil)
			SoMsg("Revocation 2", intfs.Get(2).Revocation(), ShouldBeNil)
		})
	})
}

func TestInterfacesAll(t *testing.T) {
	Convey("Given an interface infos map with existing entries", t, func() {
		intfs := testInterfaces()
		Convey("All should return all infos", func() {
			all := intfs.All()
			// The topo info should remain.
			SoMsg("Name 1", all[1].TopoInfo().BRName, ShouldEqual, "BR-1")
			SoMsg("Name 2", all[2].TopoInfo().BRName, ShouldEqual, "BR-2")
			SoMsg("Ifid 1", all[1].TopoInfo().RemoteIFID, ShouldEqual, 11)
			SoMsg("Ifid 2", all[2].TopoInfo().RemoteIFID, ShouldEqual, 22)
			SoMsg("State 1", all[1].State(), ShouldEqual, Active)
			SoMsg("State 2", all[2].State(), ShouldEqual, Revoked)
			SoMsg("Revocation 1", all[1].Revocation(), ShouldBeNil)
			SoMsg("Revocation 2", all[2].Revocation(), ShouldNotBeNil)
		})
	})
}

func TestInfoActivate(t *testing.T) {
	for _, state := range []State{Inactive, Active, Expired, Revoked} {
		Convey("Activate switches correctly from "+string(state), t, func() {
			intf := &Interface{state: state, revocation: &path_mgmt.SignedRevInfo{}}
			intf.cfg.InitDefaults()
			prev := intf.Activate(11)
			SoMsg("State", prev, ShouldEqual, state)
			SoMsg("Active", intf.state, ShouldEqual, Active)
			SoMsg("Revocation", intf.revocation, ShouldBeNil)
			SoMsg("LastActivate", time.Now().Sub(intf.lastActivate), ShouldBeLessThanOrEqualTo,
				100*time.Millisecond)
		})
	}
}

func TestInfoExpire(t *testing.T) {
	Convey("Given an interface that has not received a keepalive", t, func() {
		testCases := []struct {
			PrevState State
			NextState State
		}{
			{PrevState: Inactive, NextState: Expired},
			{PrevState: Active, NextState: Expired},
			{PrevState: Expired, NextState: Expired},
			{PrevState: Revoked, NextState: Revoked},
		}
		for _, test := range testCases {
			Convey("Test "+string(test.PrevState), func() {
				intf := &Interface{
					state:        test.PrevState,
					lastActivate: time.Now().Add(-DefaultKeepaliveTimeout - time.Second),
				}
				intf.cfg.InitDefaults()
				expired := intf.Expire()
				SoMsg("Expired", expired, ShouldBeTrue)
				SoMsg("State", intf.State(), ShouldEqual, test.NextState)
				SoMsg("LastActivate", time.Now().Sub(intf.lastActivate), ShouldBeGreaterThan,
					DefaultKeepaliveTimeout)
			})
		}
	})
	Convey("Given the keepalive has been received in the last keepalive timeout", t, func() {
		for _, test := range []State{Inactive, Active, Expired, Revoked} {
			Convey("Test "+string(test), func() {
				intf := &Interface{
					state:        test,
					lastActivate: time.Now().Add(-DefaultKeepaliveTimeout + time.Second),
				}
				intf.cfg.InitDefaults()
				expired := intf.Expire()
				SoMsg("Expired", expired, ShouldEqual, test == Revoked || test == Expired)
				SoMsg("State", intf.State(), ShouldEqual, test)
			})
		}
	})
}

func TestInfoRevoke(t *testing.T) {
	Convey("Given an interface in a certain state", t, func() {
		testCases := []struct {
			PrevState State
			NextState State
			Error     bool
		}{
			{PrevState: Inactive, NextState: Revoked, Error: false},
			{PrevState: Active, NextState: Active, Error: true},
			{PrevState: Expired, NextState: Revoked, Error: false},
			{PrevState: Revoked, NextState: Revoked, Error: false},
		}
		for _, test := range testCases {
			Convey("Test "+string(test.PrevState), func() {
				intf := &Interface{
					state: test.PrevState,
				}
				intf.cfg.InitDefaults()
				err := intf.Revoke(&path_mgmt.SignedRevInfo{})
				SoMsg("State", intf.State(), ShouldEqual, test.NextState)
				if test.Error {
					SoMsg("err", err, ShouldNotBeNil)
					SoMsg("Revocation", intf.Revocation(), ShouldBeNil)
				} else {
					SoMsg("err", err, ShouldBeNil)
					SoMsg("Revocation", intf.Revocation(), ShouldNotBeNil)
				}
			})
		}
	})
}

func testInterfaces() *Interfaces {
	topoMap := topology.IfInfoMap{
		1: {BRName: "BR-1"},
		2: {BRName: "BR-2"},
	}
	intfs := NewInterfaces(topoMap, Config{})
	intfs.Get(1).Activate(11)
	intfs.Get(2).topoInfo.RemoteIFID = 22
	intfs.Get(2).Revoke(&path_mgmt.SignedRevInfo{})
	return intfs
}
