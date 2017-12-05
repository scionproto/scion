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
	"fmt"
	"net"
	"testing"
	"time"

	// External
	. "github.com/smartystreets/goconvey/convey"

	// Local
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
)

var testTopo *Topo

// Helpers
func mkTAv4(ip string, port int, bindip string, bindport int, ot overlay.Type, op int) TopoAddr {
	if bindip == "" {
		return TopoAddr{IPv4: &topoAddrInt{pubIP: net.ParseIP(ip), pubL4Port: port, OverlayPort: op}, Overlay: ot}
	}
	tai := &topoAddrInt{
		pubIP: net.ParseIP(ip), pubL4Port: port,
		bindIP: net.ParseIP(bindip), bindL4Port: bindport,
		OverlayPort: op,
	}
	return TopoAddr{IPv4: tai, Overlay: ot}
}

func mkTAv6(ip string, port int, bindip string, bindport int, ot overlay.Type, op int) TopoAddr {
	if bindip == "" {
		return TopoAddr{IPv6: &topoAddrInt{pubIP: net.ParseIP(ip), pubL4Port: port, OverlayPort: op}, Overlay: ot}
	}
	tai := &topoAddrInt{
		pubIP: net.ParseIP(ip), pubL4Port: port,
		bindIP: net.ParseIP(bindip), bindL4Port: bindport,
		OverlayPort: op,
	}
	return TopoAddr{IPv6: tai, Overlay: ot}
}

func loadTopo(filename string, t *testing.T) {
	topo, err := LoadFromFile(filename)
	if err != nil {
		t.Fatalf("Error loading config from '%s': %v", filename, err)
	}
	testTopo = topo
}

func Test_Meta(t *testing.T) {
	fn := "testdata/basic.json"
	Convey("Checking metadata", t, func() {
		loadTopo(fn, t)
		c := testTopo
		SoMsg("Checking field 'Timestamp'", c.Timestamp.Equal(time.Unix(168570123, 0)), ShouldBeTrue)
		// Is testing this piece of data really useful?
		SoMsg("Checking field 'TimestampHuman", c.TimestampHuman,
			ShouldContainSubstring, "1975-05-06 01:02:03.000000+0000")
		SoMsg("Checking field 'ISD_AS'", c.ISD_AS, ShouldResemble, &addr.ISD_AS{I: 1, A: 11})
		SoMsg("Checking field 'Overlay'", c.Overlay, ShouldEqual, overlay.IPv46)
		SoMsg("Checking field 'MTU'", c.MTU, ShouldEqual, 1472)
		SoMsg("Checking field 'Core'", c.Core, ShouldBeFalse)

	})
}

func Test_BRs(t *testing.T) {
	brs := map[string]BRInfo{
		"br1-11-1": {
			IFIDs: []common.IFIDType{1, 3, 8},
		},
	}
	brn := []string{"br1-11-1"}

	fn := "testdata/basic.json"
	loadTopo(fn, t)
	c := testTopo
	for name, info := range brs {
		Convey(fmt.Sprintf("Checking BR details for %s", name), t, func() {
			So(c.BR, ShouldContainKey, name)
			for _, i := range info.IFIDs {
				Convey(fmt.Sprintf("Checking if %s has interface with id %v", name, i), func() {
					So(c.BR[name].IFIDs, ShouldContain, i)
				})
			}
			So(c.BRNames, ShouldResemble, brn)
		})
	}
	Convey("Checking that BR map has no extra entries ", t, func() { So(len(c.BR), ShouldEqual, len(brn)) })
}

func Test_Service_Details(t *testing.T) {
	fn := "testdata/basic.json"
	ot := overlay.IPv46
	// We do this just for CSs since the code for the other non-BR, non-ZK services is identical
	cses := map[string]TopoAddr{
		// v4 with bind
		"cs1-11-1": mkTAv4("127.0.0.66", 30081, "127.0.0.67", 30081, ot, 0),
		// v4 without bind
		"cs1-11-2": mkTAv4("127.0.0.67", 30073, "", 0, ot, 0),
		// v6 without bind
		"cs1-11-3": mkTAv6("2001:db8:f00:b43::1", 23421, "", 0, ot, 0),
		// v6 with bind
		"cs1-11-4": mkTAv6("2001:db8:f00:b43::2", 23421, "2001:db8:1714::1", 13373, ot, 0),
	}
	loadTopo(fn, t)
	c := testTopo
	for name := range cses {
		Convey(fmt.Sprintf("Checking service details for %s", name), t, func() {
			So(c.CS[name], ShouldResemble, cses[name])
		})
	}
	Convey("Checking if CS map has extra entries", t, func() {
		So(len(c.CS), ShouldEqual, len(cses))
	})
}

func Test_Service_Count(t *testing.T) {
	// This just checks the count of all the service types, actual population testing is done elsewhere
	// The simple counting check for CS is done in the detailed population test as well
	fn := "testdata/basic.json"
	loadTopo(fn, t)
	c := testTopo
	Convey(fmt.Sprintf("Checking count of service entries"), t, func() {
		SoMsg("Checking BS", len(c.BS), ShouldEqual, 3)
		SoMsg("Checking PS", len(c.PS), ShouldEqual, 2)
		SoMsg("Checking SB", len(c.SB), ShouldEqual, 2)
		SoMsg("Checking RS", len(c.RS), ShouldEqual, 2)
		SoMsg("Checking DS", len(c.DS), ShouldEqual, 2)
	})

}

func Test_ZK(t *testing.T) {
	zks := map[int]TopoAddr{
		1: mkTAv4("192.0.2.144", 2181, "", 0, overlay.IPv46, 0),
		2: mkTAv6("2001:db8:ffff::1", 2181, "", 0, overlay.IPv46, 0),
	}
	fn := "testdata/basic.json"
	loadTopo(fn, t)
	c := testTopo
	for name := range zks {
		Convey(fmt.Sprintf("Checking ZK details for ZK id %d", name), t, func() {
			So(c.ZK[name], ShouldResemble, zks[name])
		})
	}
	Convey("Checking that ZK map has no extra entries", t, func() {
		So(len(c.ZK), ShouldEqual, len(zks))
	})
}

func Test_IFInfoMap(t *testing.T) {
	ifm := make(map[common.IFIDType]IFInfo)
	isdas, _ := addr.IAFromString("1-12")
	ifm[1] = IFInfo{
		BRName: "br1-11-1",
		InternalAddr: &TopoAddr{
			IPv4:    &topoAddrInt{pubIP: net.ParseIP("10.1.0.1"), pubL4Port: 30097},
			IPv6:    &topoAddrInt{pubIP: net.ParseIP("2001:db8:a0b:12f0::1"), pubL4Port: 30097},
			Overlay: overlay.IPv46},
		Overlay: overlay.UDPIPv4,
		Local: &TopoAddr{
			IPv4: &topoAddrInt{
				pubIP: net.ParseIP("192.0.2.1"), pubL4Port: 44997,
				bindIP: net.ParseIP("10.0.0.1"), bindL4Port: 30090,
				OverlayPort: 44997,
			},
			Overlay: overlay.UDPIPv4},
		Remote: &AddrInfo{Overlay: overlay.UDPIPv4, IP: net.ParseIP("192.0.2.2"),
			L4Port: 44998, OverlayPort: 44998},
		Bandwidth: 1000,
		ISD_AS:    isdas,
		LinkType:  ParentLink,
		MTU:       1472,
	}
	isdas, _ = addr.IAFromString("1-14")
	ifm[3] = IFInfo{
		BRName: "br1-11-1",
		InternalAddr: &TopoAddr{
			IPv4:    &topoAddrInt{pubIP: net.ParseIP("10.1.0.1"), pubL4Port: 30097},
			IPv6:    &topoAddrInt{pubIP: net.ParseIP("2001:db8:a0b:12f0::1"), pubL4Port: 30097},
			Overlay: overlay.IPv46},
		Overlay: overlay.IPv6,
		Local: &TopoAddr{
			IPv6: &topoAddrInt{
				pubIP: net.ParseIP("2001:db8:a0b:12f0::1"), pubL4Port: 50000,
				bindIP: net.ParseIP("2001:db8:a0b:12f0::8"), bindL4Port: 10000,
			},
			Overlay: overlay.IPv6},
		Remote: &AddrInfo{Overlay: overlay.IPv6, IP: net.ParseIP("2001:db8:a0b:12f0::2"), L4Port: 50000},

		Bandwidth: 5000,
		ISD_AS:    isdas,
		LinkType:  ChildLink,
		MTU:       4430,
	}
	isdas, _ = addr.IAFromString("1-13")
	ifm[8] = IFInfo{
		BRName: "br1-11-1",
		InternalAddr: &TopoAddr{
			IPv4:    &topoAddrInt{pubIP: net.ParseIP("10.1.0.2"), pubL4Port: 30097},
			IPv6:    &topoAddrInt{pubIP: net.ParseIP("2001:db8:a0b:12f0::2"), pubL4Port: 30097},
			Overlay: overlay.IPv46},
		Overlay: overlay.IPv4,
		Local: &TopoAddr{
			IPv4: &topoAddrInt{
				pubIP: net.ParseIP("192.0.2.2"), pubL4Port: 50000,
				bindIP: net.ParseIP("10.0.0.2"), bindL4Port: 40000},
			Overlay: overlay.IPv4},
		Remote:    &AddrInfo{Overlay: overlay.IPv4, IP: net.ParseIP("192.0.2.3"), L4Port: 50001},
		Bandwidth: 2000,
		ISD_AS:    isdas,
		LinkType:  PeerLink,
		MTU:       1480,
	}
	fn := "testdata/basic.json"
	loadTopo(fn, t)
	for _, id := range []common.IFIDType{1, 3, 8} {
		Convey(fmt.Sprintf("Checking IFInfoMap entry for Interface %d", id), t, func() {
			c := testTopo
			So(c.IFInfoMap[id], ShouldResemble, ifm[id])
		})
	}

}

var l4port_extract_cases = []struct {
	intopo  TopoAddr
	inae    addr.HostAddr
	outint  int
	outbool bool
}{
	// Non working cases
	// topo and overlay agree, addr mismatch
	{mkTAv4("127.0.0.1", 3000, "", 0, overlay.IPv4, 0), addr.HostIPv6(net.ParseIP("::1")), 0, false},
	// topo and addr agree, overlay mismatch
	{mkTAv6("::1", 3000, "", 0, overlay.IPv4, 0), addr.HostIPv6(net.ParseIP("::1")), 0, false},
	// overlay and addr agree, topo mismatch
	{mkTAv6("::1", 3000, "", 0, overlay.IPv4, 0), addr.HostIPv4(net.ParseIP("127.0.0.1")), 0, false},
	// overlay support both v4 and v6, but topo and addr disagree
	{mkTAv6("::1", 3000, "", 0, overlay.IPv46, 0), addr.HostIPv4(net.ParseIP("127.0.0.1")), 0, false},

	// Working cases
	// all-v6
	{mkTAv6("::1", 3000, "", 0, overlay.IPv6, 0), addr.HostIPv6(net.ParseIP("::1")), 3000, true},
	// all-v4
	{mkTAv4("127.0.0.1", 3000, "", 0, overlay.IPv4, 0), addr.HostIPv4(net.ParseIP("127.0.0.1")), 3000, true},
	// v4 topo, v4 addr, v4/v6 overlay
	{mkTAv4("127.0.0.1", 3000, "", 0, overlay.IPv46, 0), addr.HostIPv4(net.ParseIP("127.0.0.1")), 3000, true},
	// v6 topo, v6 addr, v4/v6 overlay
	{mkTAv6("::1", 3000, "", 0, overlay.IPv46, 0), addr.HostIPv6(net.ParseIP("::1")), 3000, true},
}

func Test_PubL4PortFromAddr(t *testing.T) {
	Convey("Testing L4 port extraction", t, func() {
		for _, tt := range l4port_extract_cases {
			Convey(fmt.Sprintf("%+v %+v -> %v %v", tt.intopo, tt.inae, tt.outint, tt.outbool), func() {
				oi, ob, _ := tt.intopo.PubL4PortFromAddr(tt.inae)
				So(oi, ShouldEqual, tt.outint)
				So(ob, ShouldEqual, tt.outbool)
			})
		}
	})
}

var mkai_cases = []struct {
	intopo   TopoAddr
	inot     overlay.Type
	inpublic bool
	outai    *AddrInfo
}{
	{mkTAv4("127.0.0.1", 3000, "", 0, overlay.IPv4, 0),
		overlay.IPv4, true,
		&AddrInfo{Overlay: overlay.IPv4, IP: net.ParseIP("127.0.0.1"), L4Port: 3000, OverlayPort: 0}},
	{mkTAv6("::1", 3000, "", 0, overlay.IPv6, 0),
		overlay.IPv6, true,
		&AddrInfo{Overlay: overlay.IPv6, IP: net.ParseIP("::1"), L4Port: 3000, OverlayPort: 0}},
	{mkTAv6("::1", 3000, "", 0, overlay.UDPIPv6, 10000),
		overlay.UDPIPv6, true,
		&AddrInfo{Overlay: overlay.UDPIPv6, IP: net.ParseIP("::1"), L4Port: 3000, OverlayPort: 10000}},
	// These cases result in nil due to overlay/address type mismatch
	{mkTAv4("127.0.0.1", 3000, "", 0, overlay.IPv4, 0),
		overlay.UDPIPv6, true,
		nil},
	{mkTAv6("::1", 3000, "", 0, overlay.UDPIPv6, 10000),
		overlay.UDPIPv4, true,
		nil},
}

func Test_addrInfo(t *testing.T) {
	Convey("Testing generation of AddrInfo from TopoAddr", t, func() {
		for _, tt := range mkai_cases {
			Convey(fmt.Sprintf("%v %v %v -> %v", tt.intopo, tt.inot, tt.inpublic, tt.outai), func() {
				ai := tt.intopo.addrInfo(tt.inot, tt.inpublic)
				So(ai, ShouldResemble, tt.outai)
			})
		}
	})
}
func Test_IFInfoMap_COREAS(t *testing.T) {
	ifm := make(map[common.IFIDType]IFInfo)
	isdas, _ := addr.IAFromString("6-23")
	ifm[91] = IFInfo{
		BRName: "borderrouter6-22-1",
		InternalAddr: &TopoAddr{
			IPv4:    &topoAddrInt{pubIP: net.ParseIP("10.1.0.1"), pubL4Port: 30097},
			IPv6:    &topoAddrInt{pubIP: net.ParseIP("2001:db8:a0b:12f0::1"), pubL4Port: 30097},
			Overlay: overlay.IPv46},
		Overlay: overlay.UDPIPv4,
		Local: &TopoAddr{
			IPv4: &topoAddrInt{
				pubIP: net.ParseIP("192.0.2.1"), pubL4Port: 4997,
				bindIP: net.ParseIP("10.0.0.1"), bindL4Port: 3090,
				OverlayPort: 4997,
			},
			Overlay: overlay.UDPIPv4},
		Remote: &AddrInfo{Overlay: overlay.UDPIPv4, IP: net.ParseIP("192.0.2.2"),
			L4Port: 4998, OverlayPort: 4998},
		Bandwidth: 100000,
		ISD_AS:    isdas,
		LinkType:  CoreLink,
		MTU:       1472,
	}
	isdas, _ = addr.IAFromString("6-14")
	ifm[32] = IFInfo{
		BRName: "borderrouter6-22-9",
		InternalAddr: &TopoAddr{
			IPv4:    &topoAddrInt{pubIP: net.ParseIP("10.1.0.2"), pubL4Port: 3097},
			IPv6:    &topoAddrInt{pubIP: net.ParseIP("2001:db8:a0b:12f0::2"), pubL4Port: 3097},
			Overlay: overlay.IPv46},
		Overlay: overlay.IPv6,
		Local: &TopoAddr{
			IPv6: &topoAddrInt{
				pubIP: net.ParseIP("2001:db8:a0b:12f0::1"), pubL4Port: 50000,
				bindIP: net.ParseIP("2001:db8:a0b:12f0::8"), bindL4Port: 10000,
			},
			Overlay: overlay.IPv6},
		Remote: &AddrInfo{Overlay: overlay.IPv6, IP: net.ParseIP("2001:db8:a0b:12f0::2"), L4Port: 50000},

		Bandwidth: 5000,
		ISD_AS:    isdas,
		LinkType:  ChildLink,
		MTU:       4430,
	}
	fn := "testdata/core.json"
	loadTopo(fn, t)
	for _, id := range []common.IFIDType{91, 32} {
		Convey(fmt.Sprintf("Checking IFInfoMap entry for Interface %d", id), t, func() {
			c := testTopo
			So(c.IFInfoMap[id], ShouldResemble, ifm[id])
		})
	}

}

var br_cases = []struct {
	name    string
	intfids []common.IFIDType
}{
	{name: "borderrouter6-22-1", intfids: []common.IFIDType{91}},
	{name: "borderrouter6-22-9", intfids: []common.IFIDType{32}},
}

func Test_BRs_COREAS(t *testing.T) {
	fn := "testdata/core.json"
	loadTopo(fn, t)
	c := testTopo
	for _, case_ := range br_cases {
		Convey(fmt.Sprintf("Checking BR details for %s", case_.name), t, func() {
			Convey(fmt.Sprintf("Checking whether topo has a BR named %s", case_.name), func() {
				So(c.BR, ShouldContainKey, case_.name)
			})
			for _, i := range case_.intfids {
				Convey(fmt.Sprintf("Checking if %s has interface with id %v", case_.name, i), func() {
					So(c.BR[case_.name].IFIDs, ShouldContain, i)
				})
			}
		})
	}
	Convey("Checking if the number of BRs in the Topo is correct", t, func() {
		So(len(c.BR), ShouldEqual, len(br_cases))
	})
}
