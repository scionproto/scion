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
