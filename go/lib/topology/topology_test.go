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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/proto"
)

var testTopo *Topo

// Helpers
func mkO(l3 addr.HostAddr, op int) *overlay.OverlayAddr {
	var o *overlay.OverlayAddr
	if op == 0 {
		o, _ = overlay.NewOverlayAddr(l3, nil)
	} else {
		o, _ = overlay.NewOverlayAddr(l3, addr.NewL4UDPInfo(uint16(op)))
	}
	return o
}

func mkOv4(ip string, port int) *overlay.OverlayAddr {
	return mkO(addr.HostIPv4(net.ParseIP(ip)), port)
}

func mkOv6(ip string, port int) *overlay.OverlayAddr {
	return mkO(addr.HostIPv6(net.ParseIP(ip)), port)
}

func mkPBO(pub, bind addr.HostAddr, port, bindport, op int) *pubBindAddr {
	pbo := &pubBindAddr{}
	pbo.pub = &addr.AppAddr{L3: pub}
	if port != 0 {
		pbo.pub.L4 = addr.NewL4UDPInfo(uint16(port))
	}
	if bind != nil {
		pbo.bind = &addr.AppAddr{L3: bind}
		if bindport != 0 {
			pbo.bind.L4 = addr.NewL4UDPInfo(uint16(bindport))
		}
	}
	pbo.overlay = mkO(pub, op)
	return pbo
}

func mkPBOv4(ip string, port int, bindip string, bindport int, op int) *pubBindAddr {
	pub := addr.HostIPv4(net.ParseIP(ip))
	var bind addr.HostAddr
	if bindip != "" {
		bind = addr.HostIPv4(net.ParseIP(bindip))
	}
	return mkPBO(pub, bind, port, bindport, op)
}

func mkPBOv6(ip string, port int, bindip string, bindport int, op int) *pubBindAddr {
	pub := addr.HostIPv6(net.ParseIP(ip))
	var bind addr.HostAddr
	if bindip != "" {
		bind = addr.HostIPv6(net.ParseIP(bindip))
	}
	return mkPBO(pub, bind, port, bindport, op)
}

func mkTAv4(ip string, port int, bindip string, bindport int, ot overlay.Type, op int) TopoAddr {
	pbo := mkPBOv4(ip, port, bindip, bindport, op)
	return TopoAddr{IPv4: pbo, Overlay: ot}
}

func mkTAv6(ip string, port int, bindip string, bindport int, ot overlay.Type, op int) TopoAddr {
	pbo := mkPBOv6(ip, port, bindip, bindport, op)
	return TopoAddr{IPv6: pbo, Overlay: ot}
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
		SoMsg("Checking field 'ISD_AS'", c.ISD_AS, ShouldResemble, addr.IA{I: 1, A: 0xff0000000311})
		SoMsg("Checking field 'Overlay'", c.Overlay, ShouldEqual, overlay.IPv46)
		SoMsg("Checking field 'MTU'", c.MTU, ShouldEqual, 1472)
		SoMsg("Checking field 'Core'", c.Core, ShouldBeFalse)

	})
}

func Test_BRs(t *testing.T) {
	brs := map[string]BRInfo{
		"br1-ff00:0:311-1": {
			IFIDs: []common.IFIDType{1, 3, 8},
		},
	}
	brn := []string{"br1-ff00:0:311-1"}

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
		"cs1-ff00:0:311-1": mkTAv4("127.0.0.66", 30081, "127.0.0.67", 30081, ot, 0),
		// v4 without bind
		"cs1-ff00:0:311-2": mkTAv4("127.0.0.67", 30073, "", 0, ot, 0),
		// v6 without bind
		"cs1-ff00:0:311-3": mkTAv6("2001:db8:f00:b43::1", 23421, "", 0, ot, 0),
		// v6 with bind
		"cs1-ff00:0:311-4": mkTAv6("2001:db8:f00:b43::2", 23421, "2001:db8:1714::1", 13373, ot, 0),
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
	// This just checks the count of all the service types, actual population
	// testing is done elsewhere
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
	isdas, _ := addr.IAFromString("1-ff00:0:312")
	ifm[1] = IFInfo{
		BRName: "br1-ff00:0:311-1",
		InternalAddr: &TopoAddr{
			IPv4:    mkPBOv4("10.1.0.1", 30097, "", 0, 0),
			IPv6:    mkPBOv6("2001:db8:a0b:12f0::1", 30097, "", 0, 0),
			Overlay: overlay.IPv46},
		Overlay: overlay.UDPIPv4,
		Local: &TopoAddr{
			IPv4:    mkPBOv4("192.0.2.1", 44997, "10.0.0.1", 30090, 44997),
			Overlay: overlay.UDPIPv4},
		Remote:    mkOv4("192.0.2.2", 44998),
		Bandwidth: 1000,
		ISD_AS:    isdas,
		LinkType:  proto.LinkType_parent,
		MTU:       1472,
	}
	isdas, _ = addr.IAFromString("1-ff00:0:314")
	ifm[3] = IFInfo{
		BRName: "br1-ff00:0:311-1",
		InternalAddr: &TopoAddr{
			IPv4:    mkPBOv4("10.1.0.1", 30097, "", 0, 0),
			IPv6:    mkPBOv6("2001:db8:a0b:12f0::1", 30097, "", 0, 0),
			Overlay: overlay.IPv46},
		Overlay: overlay.IPv6,
		Local: &TopoAddr{
			IPv6:    mkPBOv6("2001:db8:a0b:12f0::1", 50000, "2001:db8:a0b:12f0::8", 10000, 0),
			Overlay: overlay.IPv6},
		Remote:    mkOv6("2001:db8:a0b:12f0::2", 0),
		Bandwidth: 5000,
		ISD_AS:    isdas,
		LinkType:  proto.LinkType_child,
		MTU:       4430,
	}
	isdas, _ = addr.IAFromString("1-ff00:0:313")
	ifm[8] = IFInfo{
		BRName: "br1-ff00:0:311-1",
		InternalAddr: &TopoAddr{
			IPv4:    mkPBOv4("10.1.0.1", 30097, "", 0, 0),
			IPv6:    mkPBOv6("2001:db8:a0b:12f0::1", 30097, "", 0, 0),
			Overlay: overlay.IPv46},
		Overlay: overlay.IPv4,
		Local: &TopoAddr{
			IPv4:    mkPBOv4("192.0.2.2", 50000, "10.0.0.2", 40000, 0),
			Overlay: overlay.IPv4},
		Remote:    mkOv4("192.0.2.3", 0),
		Bandwidth: 2000,
		ISD_AS:    isdas,
		LinkType:  proto.LinkType_peer,
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

func Test_IFInfoMap_COREAS(t *testing.T) {
	ifm := make(map[common.IFIDType]IFInfo)
	isdas, _ := addr.IAFromString("6-ff00:0:363")
	ifm[91] = IFInfo{
		BRName: "borderrouter6-ff00:0:362-1",
		InternalAddr: &TopoAddr{
			IPv4:    mkPBOv4("10.1.0.1", 30097, "", 0, 0),
			IPv6:    mkPBOv6("2001:db8:a0b:12f0::1", 30097, "", 0, 0),
			Overlay: overlay.IPv46},
		Overlay: overlay.UDPIPv4,
		Local: &TopoAddr{
			IPv4:    mkPBOv4("192.0.2.1", 4997, "10.0.0.1", 3090, 4997),
			Overlay: overlay.UDPIPv4},
		Remote:    mkOv4("192.0.2.2", 4998),
		Bandwidth: 100000,
		ISD_AS:    isdas,
		LinkType:  proto.LinkType_core,
		MTU:       1472,
	}
	isdas, _ = addr.IAFromString("6-ff00:0:364")
	ifm[32] = IFInfo{
		BRName: "borderrouter6-ff00:0:362-9",
		InternalAddr: &TopoAddr{
			IPv4:    mkPBOv4("10.1.0.2", 3097, "", 0, 0),
			IPv6:    mkPBOv6("2001:db8:a0b:12f0::2", 3097, "", 0, 0),
			Overlay: overlay.IPv46},
		Overlay: overlay.IPv6,
		Local: &TopoAddr{
			IPv6:    mkPBOv6("2001:db8:a0b:12f0::1", 50000, "2001:db8:a0b:12f0::8", 10000, 0),
			Overlay: overlay.IPv6},
		Remote:    mkOv6("2001:db8:a0b:12f0::2", 0),
		Bandwidth: 5000,
		ISD_AS:    isdas,
		LinkType:  proto.LinkType_child,
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

func Test_IFInfo_InternalAddr(t *testing.T) {
	ifm := make(map[common.IFIDType]*TopoAddr)
	ifm[101] = &TopoAddr{
		IPv4:    mkPBOv4("192.0.128.1", 30097, "10.0.0.1", 30197, 30097),
		IPv6:    mkPBOv6("2001:db8:a0b:12f0::1", 30098, "fe80::", 30198, 30098),
		Overlay: overlay.UDPIPv46,
	}
	fn := "testdata/udpbr.json"
	loadTopo(fn, t)
	for _, id := range []common.IFIDType{101} {
		Convey(fmt.Sprintf("Checking IFInfoMap entry for Interface %d", id), t, func() {
			c := testTopo
			So(c.IFInfoMap[id].InternalAddr, ShouldResemble, ifm[id])
		})
	}
}

var br_cases = []struct {
	name    string
	intfids []common.IFIDType
}{
	{name: "borderrouter6-ff00:0:362-1", intfids: []common.IFIDType{91}},
	{name: "borderrouter6-ff00:0:362-9", intfids: []common.IFIDType{32}},
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
				Convey(fmt.Sprintf("Checking if %s has interface with id %v", case_.name, i),
					func() {
						So(c.BR[case_.name].IFIDs, ShouldContain, i)
					})
			}
		})
	}
	Convey("Checking if the number of BRs in the Topo is correct", t, func() {
		So(len(c.BR), ShouldEqual, len(br_cases))
	})
}
