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

	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var fn = "testdata/topo.json"

func TestGeneralValidatorGeneral(t *testing.T) {
	Convey("Given a general validator", t, func() {
		v := generalValidator{}
		Convey("A nil topology is not valid", func() {
			SoMsg("err", v.General(nil), ShouldNotBeNil)
		})
		Convey("A topology should be valid", func() {
			SoMsg("err", v.General(loadTopo(fn, t)), ShouldBeNil)
		})
	})
}

func TestGeneralValidatorImmutable(t *testing.T) {
	Convey("Given a general validator", t, func() {
		oldTopo := loadTopo(fn, t)
		topo := loadTopo(fn, t)
		testGenImmutable(&generalValidator{}, topo, oldTopo, t)
	})
}

func TestSvcValidatorGeneral(t *testing.T) {
	Convey("Given a service validator", t, func() {
		v := &svcValidator{id: "cs1-ff00:0:311-1", svc: proto.ServiceType_cs}
		Convey("A nil topology is not valid", func() {
			SoMsg("err", v.General(nil), ShouldNotBeNil)
		})
		Convey("The topology is only valid if it contains the service", func() {
			topo := loadTopo(fn, t)
			SoMsg("Err contained", v.General(topo), ShouldBeNil)
			v.id = "missing"
			SoMsg("Err missing", v.General(topo), ShouldNotBeNil)
		})
	})
}

func TestSvcValidatorImmutable(t *testing.T) {
	Convey("Given a service validator", t, func() {
		v := &svcValidator{id: "cs1-ff00:0:311-1", svc: proto.ServiceType_cs}
		other := "cs1-ff00:0:311-2"
		oldTopo := loadTopo(fn, t)
		topo := loadTopo(fn, t)
		testGenImmutable(v, topo, oldTopo, t)
		Convey("Modifying a different service of the same type is allowed", func() {
			svcInfo := topo.CS[other]
			svcInfo.Overlay = overlay.IPv6
			topo.CS[other] = svcInfo
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldBeNil)
		})
		Convey("Modifying the own service entry is not allowed", func() {
			svcInfo := topo.CS[v.id]
			svcInfo.Overlay = overlay.IPv6
			topo.CS[v.id] = svcInfo
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
		})
	})
}

func TestBrValidatorGeneral(t *testing.T) {
	Convey("Given a border router validator", t, func() {
		v := brValidator{id: "br1-ff00:0:311-1"}
		Convey("A nil topology is not valid", func() {
			SoMsg("err", v.General(nil), ShouldNotBeNil)
		})
		Convey("The topology is only valid if it contains the border router", func() {
			topo := loadTopo(fn, t)
			SoMsg("Err contained", v.General(topo), ShouldBeNil)
			v.id = "missing"
			SoMsg("Err missing", v.General(topo), ShouldNotBeNil)
		})
	})
}

func TestBrValidatorImmutable(t *testing.T) {
	Convey("Given a border router validator", t, func() {
		v := &brValidator{id: "br1-ff00:0:311-1"}
		other := "br1-ff00:0:311-2"
		oldTopo := loadTopo(fn, t)
		topo := loadTopo(fn, t)
		testGenImmutable(v, topo, oldTopo, t)
		Convey("Modifying a different br's internal address is allowed", func() {
			brInfo := topo.BR[other]
			brInfo.InternalAddrs.Overlay = overlay.IPv6
			topo.BR[other] = brInfo
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldBeNil)
		})
		Convey("Modifying a different br's control address is allowed", func() {
			brInfo := topo.BR[other]
			brInfo.CtrlAddrs.Overlay = overlay.IPv6
			topo.BR[other] = brInfo
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldBeNil)
		})
		Convey("Modifying the own internal address is not allowed", func() {
			brInfo := topo.BR[v.id]
			brInfo.InternalAddrs.Overlay = overlay.IPv6
			topo.BR[v.id] = brInfo
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
		})
		Convey("Modifying the own control address is not allowed", func() {
			brInfo := topo.BR[v.id]
			brInfo.CtrlAddrs.Overlay = overlay.IPv6
			topo.BR[v.id] = brInfo
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
		})
	})
}

func TestBrValidatorSemiMutable(t *testing.T) {
	Convey("Given a border router validator", t, func() {
		v := &brValidator{id: "br1-ff00:0:311-1"}
		other := "br1-ff00:0:311-2"
		oldTopo := loadTopo(fn, t)
		topo := loadTopo(fn, t)
		Convey("And semi-mutation is allowed", func() {
			Convey("Adding a new interface is allowed", func() {
				brInfo := topo.BR[v.id]
				brInfo.IFIDs = append(brInfo.IFIDs, 42)
				topo.BR[v.id] = brInfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, true), ShouldBeNil)
			})
			Convey("Modifying an interface is allowed", func() {
				ifinfo := topo.IFInfoMap[1]
				ifinfo.MTU = 42
				topo.IFInfoMap[1] = ifinfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, true), ShouldBeNil)
			})
			Convey("Deleting an interface is allowed", func() {
				brInfo := topo.BR[v.id]
				brInfo.IFIDs = brInfo.IFIDs[1:]
				topo.BR[v.id] = brInfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, true), ShouldBeNil)
			})
			Convey("Adding and deleting an interface is allowed", func() {
				brInfo := topo.BR[v.id]
				brInfo.IFIDs = append(brInfo.IFIDs, 42)
				brInfo.IFIDs = brInfo.IFIDs[1:]
				topo.BR[v.id] = brInfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, true), ShouldBeNil)
			})
			Convey("No modification is allowed", func() {
				SoMsg("err", v.SemiMutable(topo, oldTopo, true), ShouldBeNil)
			})
			Convey("Modification of different br is allowed", func() {
				brInfo := topo.BR[other]
				brInfo.IFIDs = append(brInfo.IFIDs, 42)
				brInfo.IFIDs = brInfo.IFIDs[1:]
				topo.BR[other] = brInfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, true), ShouldBeNil)
			})
		})
		Convey("And semi-mutation is not allowed", func() {
			Convey("Adding a new interface is not allowed", func() {
				brInfo := topo.BR[v.id]
				brInfo.IFIDs = append(brInfo.IFIDs, 42)
				topo.BR[v.id] = brInfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, false), ShouldNotBeNil)
			})
			Convey("Modifying an interface is not allowed", func() {
				ifinfo := topo.IFInfoMap[1]
				ifinfo.MTU = 42
				topo.IFInfoMap[1] = ifinfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, false), ShouldNotBeNil)
			})
			Convey("Deleting an interface is not allowed", func() {
				brInfo := topo.BR[v.id]
				brInfo.IFIDs = brInfo.IFIDs[1:]
				topo.BR[v.id] = brInfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, false), ShouldNotBeNil)
			})
			Convey("Adding and deleting an interface is not allowed", func() {
				brInfo := topo.BR[v.id]
				brInfo.IFIDs = append(brInfo.IFIDs, 42)
				brInfo.IFIDs = brInfo.IFIDs[1:]
				topo.BR[v.id] = brInfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, false), ShouldNotBeNil)
			})
			Convey("No modification is allowed", func() {
				SoMsg("err", v.SemiMutable(topo, oldTopo, false), ShouldBeNil)
			})
			Convey("Modification of different br is allowed", func() {
				brInfo := topo.BR[other]
				brInfo.IFIDs = append(brInfo.IFIDs, 42)
				brInfo.IFIDs = brInfo.IFIDs[1:]
				topo.BR[other] = brInfo
				SoMsg("err", v.SemiMutable(topo, oldTopo, false), ShouldBeNil)
			})
		})
	})
}

func TestBrValidatorMustDropDynamic(t *testing.T) {
	Convey("Given a border router validator", t, func() {
		v := &brValidator{id: "br1-ff00:0:311-1"}
		oldTopo := loadTopo(fn, t)
		topo := loadTopo(fn, t)

		Convey("Adding a new interface forces a drop", func() {
			brInfo := topo.BR[v.id]
			brInfo.IFIDs = append(brInfo.IFIDs, 42)
			topo.BR[v.id] = brInfo
			SoMsg("drop", v.MustDropDynamic(topo, oldTopo), ShouldBeTrue)
		})
		Convey("Modifying an interface forces a drop", func() {
			ifinfo := topo.IFInfoMap[1]
			ifinfo.MTU = 42
			topo.IFInfoMap[1] = ifinfo
			SoMsg("drop", v.MustDropDynamic(topo, oldTopo), ShouldBeTrue)
		})
		Convey("Deleting an interface forces a drop", func() {
			brInfo := topo.BR[v.id]
			brInfo.IFIDs = brInfo.IFIDs[1:]
			topo.BR[v.id] = brInfo
			SoMsg("drop", v.MustDropDynamic(topo, oldTopo), ShouldBeTrue)
		})
	})
}

func testGenImmutable(v internalValidator, topo, oldTopo *topology.Topo, t *testing.T) {
	t.Helper()
	Convey("Updating the IA is not allowed", func() {
		topo.ISD_AS.I = 0
		SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
	})
	Convey("Updating the core flag is not allowed", func() {
		topo.Core = true
		SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
	})
	Convey("Updating the overlay is not allowed", func() {
		topo.Overlay = overlay.IPv6
		SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
	})
	Convey("Updating the mtu is not allowed", func() {
		topo.MTU = 42
		SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
	})
	Convey("Changing a mutable field is allowed", func() {
		topo.TTL = time.Second
	})
}

func loadTopo(filename string, t *testing.T) *topology.Topo {
	t.Helper()
	topo, err := topology.LoadFromFile(filename)
	if err != nil {
		t.Fatalf("Error loading config from '%s': %v", filename, err)
	}
	return topo
}
