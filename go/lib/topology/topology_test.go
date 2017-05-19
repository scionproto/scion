// Copyright 2016 ETH Zurich
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

package topology

import (
	// Stdlib
	"net"
	"testing"

	// External
	. "github.com/smartystreets/goconvey/convey"

	// Local
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/util"
)

func Test_Topo(t *testing.T) {
	// Lots of setup
	bses := map[string]BasicElem{
		"bs1-11-1": {mkYIP("127.0.0.65"), 30054},
	}
	cses := map[string]BasicElem{
		"cs1-11-1": {mkYIP("127.0.0.66"), 30081},
		"cs1-11-2": {mkYIP("127.0.0.67"), 30073},
	}
	brs := map[string]TopoBR{
		"br1-11-1": {
			BasicElem{mkYIP("127.0.0.69"), 30097},
			&TopoIF{mkYIP("127.0.0.6"), 50001, mkYIP("127.0.0.7"), 50000,
				1, &addr.ISD_AS{I: 1, A: 12}, 1472, 1000, "CORE"},
		},
	}
	pses := map[string]BasicElem{
		"ps1-11-1": {mkYIP("127.0.0.73"), 30091},
	}
	sbs := map[string]BasicElem{
		"sb1-11-1": {mkYIP("127.0.0.76"), 30058},
	}
	zks := map[int]BasicElem{
		1: {mkYIP("127.0.0.1"), 2181},
	}
	core := true
	ia := &addr.ISD_AS{I: 1, A: 11}
	mtu := 1472

	// Finally testing
	Convey("Loading test config `testdata/basic.yml`", t, func() {
		tm, err := Load("testdata/basic.yml")
		if err != nil {
			t.Fatalf("Error loading config: %v", err)
		}
		c := tm.T
		So(c.BS, ShouldResemble, bses)
		So(c.CS, ShouldResemble, cses)
		So(c.BR, ShouldResemble, brs)
		So(c.PS, ShouldResemble, pses)
		So(c.SB, ShouldResemble, sbs)
		So(c.ZK, ShouldResemble, zks)
		So(c.Core, ShouldEqual, core)
		So(c.IA, ShouldResemble, ia)
		So(c.MTU, ShouldEqual, mtu)
		// And finally, the whole thing combined. This ensures that any fields
		// that are forgotten get noticed.
		So(c, ShouldResemble, Topo{
			BS: bses, CS: cses, BR: brs, PS: pses, SB: sbs, ZK: zks,
			Core: core, IA: ia, MTU: mtu,
		})
	})
}

func mkYIP(ip string) *util.YamlIP {
	return &util.YamlIP{IP: net.ParseIP(ip)}
}
