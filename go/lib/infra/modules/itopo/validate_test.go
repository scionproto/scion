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
	"net"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/scrypto/trc"
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
			svcInfo.UnderlayAddress = &net.UDPAddr{Port: 42}
			topo.CS[other] = svcInfo
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldBeNil)
		})
		Convey("Modifying the own service entry is not allowed", func() {
			svcInfo := topo.CS[v.id]
			svcInfo.UnderlayAddress = &net.UDPAddr{Port: 42}
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
			topo.BR[other].InternalAddr.Port = 42
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldBeNil)
		})
		Convey("Modifying a different br's control address is allowed", func() {
			topo.BR[other].CtrlAddrs.UnderlayAddress = &net.UDPAddr{Port: 42}
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldBeNil)
		})
		Convey("Modifying the own internal address is not allowed", func() {
			topo.BR[v.id].InternalAddr.Port = 42
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
		})
		Convey("Modifying the own control address is not allowed", func() {
			brInfo := topo.BR[v.id]
			brInfo.CtrlAddrs.UnderlayAddress = &net.UDPAddr{Port: 42}
			topo.BR[v.id] = brInfo
			SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
		})
	})
}

func testGenImmutable(v internalValidator, topo, oldTopo *topology.RWTopology, t *testing.T) {
	t.Helper()
	Convey("Updating the IA is not allowed", func() {
		topo.IA.I = 0
		SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
	})
	Convey("Updating the attributes is not allowed", func() {
		topo.Attributes = trc.Attributes{trc.Core}
		SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
	})
	Convey("Updating the mtu is not allowed", func() {
		topo.MTU = 42
		SoMsg("err", v.Immutable(topo, oldTopo), ShouldNotBeNil)
	})
	Convey("Changing a mutable field is allowed", func() {
		topo.Timestamp = oldTopo.Timestamp.Add(time.Hour)
	})
}

func loadTopo(filename string, t *testing.T) *topology.RWTopology {
	t.Helper()
	topo, err := topology.RWTopologyFromJSONFile(filename)
	if err != nil {
		t.Fatalf("Error loading config from '%s': %v", filename, err)
	}
	topo.Timestamp = time.Now()
	return topo
}
