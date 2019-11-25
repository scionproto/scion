// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology/overlay"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func TestMeta(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")
	assert.Equal(t, time.Unix(168570123, 0), c.Timestamp, "Field 'Timestamp'")
	// Is testing this piece of data really useful?
	assert.Contains(t, c.TimestampHuman, "1975-05-06 01:02:03.000000+0000",
		"Field 'TimestampHuman'")
	assert.Equal(t, time.Hour, c.TTL, "Field 'TTL'")
	assert.Equal(t, addr.IA{I: 1, A: 0xff0000000311}, c.ISD_AS, "Field 'ISD_AS'")
	assert.Equal(t, overlay.IPv46, c.Overlay, "Field 'Overlay'")
	assert.Equal(t, 1472, c.MTU, "Field 'MTU'")
	assert.False(t, c.Core, "Field 'Core'")
}

func Test_Active(t *testing.T) {
	t.Run("positive TTL", func(t *testing.T) {
		c := MustLoadTopo(t, "testdata/basic.json")
		assert.False(t, c.Active(c.Timestamp.Add(-time.Second)))
		assert.True(t, c.Active(c.Timestamp))
		assert.True(t, c.Active(c.Timestamp.Add(c.TTL-1)))
		assert.False(t, c.Active(c.Timestamp.Add(time.Hour)))
	})
	t.Run("zero TTL", func(t *testing.T) {
		c := MustLoadTopo(t, "testdata/basic.json")
		c.TTL = 0
		assert.False(t, c.Active(c.Timestamp.Add(-time.Second)))
		assert.True(t, c.Active(c.Timestamp))
		assert.True(t, c.Active(c.Timestamp.Add(100*time.Hour)))

	})
}

func Test_BRs(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")

	brs := map[string]BRInfo{
		"br1-ff00:0:311-1": {
			IFIDs: []common.IFIDType{1, 3, 8},
		},
	}
	brn := []string{"br1-ff00:0:311-1"}

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
	Convey("Checking that BR map has no extra entries ", t, func() {
		So(len(c.BR), ShouldEqual, len(brn))
	})
}

func TestServiceDetails(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")
	cses := IDAddrMap{
		"cs1-ff00:0:311-2": TopoAddr{
			SCIONAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{127, 0, 0, 67}),
				L4: 30073,
			},
			UnderlayAddress: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 67},
				Port: 30041,
			},
		},
		"cs1-ff00:0:311-3": TopoAddr{
			SCIONAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.ParseIP("2001:db8:f00:b43::1")),
				L4: 23421,
			},
			UnderlayAddress: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:f00:b43::1"),
				Port: 30041,
			},
		},
	}
	assert.Equal(t, cses, c.CS)
}

func TestServiceCount(t *testing.T) {
	// This just checks the count of all the service types, actual population
	// testing is done elsewhere
	// The simple counting check for CS is done in the detailed population test as well
	c := MustLoadTopo(t, "testdata/basic.json")
	assert.Len(t, c.BS, 3, "BS")
	assert.Len(t, c.PS, 2, "PS")
	assert.Len(t, c.SIG, 2, "SIG")
	assert.Len(t, c.DS, 2, "DS")
}

func TestIFInfoMap(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")
	ifm := IfInfoMap{
		1: IFInfo{
			Id:     1,
			BRName: "br1-ff00:0:311-1",
			InternalAddrs: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &addr.AppAddr{
					L3: addr.HostFromIP(net.ParseIP("2001:db8:a0b:12f0::1")),
					L4: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::1"), Port: 30041},
			},
			Overlay: overlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 1},
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 2},
				Port: 44998,
			},
			Bandwidth: 1000,
			ISD_AS:    xtest.MustParseIA("1-ff00:0:312"),
			LinkType:  proto.LinkType_parent,
			MTU:       1472,
		},
		3: IFInfo{
			Id:     3,
			BRName: "br1-ff00:0:311-1",
			InternalAddrs: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &addr.AppAddr{
					L3: addr.HostFromIP(net.ParseIP("2001:db8:a0b:12f0::1")),
					L4: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::1"), Port: 30041},
			},
			Overlay: overlay.UDPIPv6,
			Local: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::8"),
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 44998,
			},
			Bandwidth: 5000,
			ISD_AS:    xtest.MustParseIA("1-ff00:0:314"),
			LinkType:  proto.LinkType_child,
			MTU:       4430,
		},
		8: IFInfo{
			Id:     8,
			BRName: "br1-ff00:0:311-1",
			InternalAddrs: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &addr.AppAddr{
					L3: addr.HostFromIP(net.ParseIP("2001:db8:a0b:12f0::1")),
					L4: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::1"), Port: 30041},
			},
			Overlay: overlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 2},
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 3},
				Port: 44998,
			},
			Bandwidth: 2000,
			ISD_AS:    xtest.MustParseIA("1-ff00:0:313"),
			LinkType:  proto.LinkType_peer,
			MTU:       1480,
		},
	}
	assert.Equal(t, ifm, c.IFInfoMap)
}

func TestIFInfoMapCoreAS(t *testing.T) {
	c := MustLoadTopo(t, "testdata/core.json")
	ifm := IfInfoMap{
		91: IFInfo{
			Id:     91,
			BRName: "borderrouter6-ff00:0:362-1",
			InternalAddrs: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &addr.AppAddr{
					L3: addr.HostFromIP(net.ParseIP("2001:db8:a0b:12f0::1")),
					L4: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::1"), Port: 30041},
			},
			Overlay: overlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 1},
				Port: 4997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 2},
				Port: 4998,
			},
			Bandwidth: 100000,
			ISD_AS:    xtest.MustParseIA("6-ff00:0:363"),
			LinkType:  proto.LinkType_core,
			MTU:       1472,
		},
		32: IFInfo{
			Id:     32,
			BRName: "borderrouter6-ff00:0:362-9",
			InternalAddrs: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &addr.AppAddr{
					L3: addr.HostFromIP(net.ParseIP("2001:db8:a0b:12f0::2")),
					L4: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::2"), Port: 30041},
			},
			Overlay: overlay.UDPIPv6,
			Local: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::8"),
				Port: 4997,
			},
			Remote: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 4998,
			},
			Bandwidth: 5000,
			ISD_AS:    xtest.MustParseIA("6-ff00:0:364"),
			LinkType:  proto.LinkType_child,
			MTU:       4430,
		},
	}
	assert.Equal(t, ifm, c.IFInfoMap)
}

func TestBRsCoreAS(t *testing.T) {
	c := MustLoadTopo(t, "testdata/core.json")
	brCases := []struct {
		name    string
		intfids []common.IFIDType
	}{
		{name: "borderrouter6-ff00:0:362-1", intfids: []common.IFIDType{91}},
		{name: "borderrouter6-ff00:0:362-9", intfids: []common.IFIDType{32}},
	}
	for _, test := range brCases {
		Convey(fmt.Sprintf("Checking BR details for %s", test.name), t, func() {
			Convey(fmt.Sprintf("Checking whether topo has a BR named %s", test.name), func() {
				So(c.BR, ShouldContainKey, test.name)
			})
			for _, i := range test.intfids {
				Convey(fmt.Sprintf("Checking if %s has interface with id %v", test.name, i),
					func() {
						So(c.BR[test.name].IFIDs, ShouldContain, i)
					})
			}
		})
	}
	Convey("Checking if the number of BRs in the Topo is correct", t, func() {
		So(len(c.BR), ShouldEqual, len(brCases))
	})
}

func TestTopoFromStripped(t *testing.T) {
	fn := "testdata/basic.json"
	rt, err := LoadRawFromFile(fn)
	require.NoError(t, err, "Error loading raw topo from '%s': %v", fn, err)
	Convey("Check that stripped bind topology can be parsed", t, func() {
		StripBind(rt)
		b, err := json.Marshal(rt)
		SoMsg("errPack", err, ShouldBeNil)
		_, err = Load(b)
		SoMsg("errParse", err, ShouldBeNil)
	})
	Convey("Check that stripped svc topology can be parsed", t, func() {
		StripServices(rt)
		b, err := json.Marshal(rt)
		SoMsg("errPack", err, ShouldBeNil)
		_, err = Load(b)
		SoMsg("errParse", err, ShouldBeNil)
	})
	Convey("Check that stripped topology can be parsed", t, func() {
		StripBind(rt)
		StripServices(rt)
		b, err := json.Marshal(rt)
		SoMsg("errPack", err, ShouldBeNil)
		_, err = Load(b)
		SoMsg("errParse", err, ShouldBeNil)
	})
}

func TestInternalDataPlanePort(t *testing.T) {
	testCases := []struct {
		Name            string
		Map             RawBRAddrMap
		ExpectedAddress *net.UDPAddr
		ExpectedError   assert.ErrorAssertionFunc
	}{
		{
			Name:          "Empty",
			Map:           RawBRAddrMap{},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad IPv4 only",
			Map: RawBRAddrMap{
				"IPv4": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "foo",
						OverlayPort: 42,
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv4 only",
			Map: RawBRAddrMap{
				"IPv4": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "127.0.0.1",
						OverlayPort: 42,
					},
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 1},
				Port: 42,
			},
		},
		{
			Name: "IPv4 contains IPv6",
			Map: RawBRAddrMap{
				"IPv4": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "::1",
						OverlayPort: 42,
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv4 with bind underlay",
			Map: RawBRAddrMap{
				"IPv4": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "127.0.0.1",
						OverlayPort: 42,
					},
					BindOverlay: &RawAddr{
						Addr: "127.255.255.255",
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad IPv6 only",
			Map: RawBRAddrMap{
				"IPv6": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "foo",
						OverlayPort: 42,
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv6 only",
			Map: RawBRAddrMap{
				"IPv6": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "::1",
						OverlayPort: 42,
					},
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 42,
			},
		},
		{
			Name: "IPv6 contains IPv4",
			Map: RawBRAddrMap{
				"IPv6": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "127.0.0.1",
						OverlayPort: 42,
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv6 with bind underlay",
			Map: RawBRAddrMap{
				"IPv6": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "::1",
						OverlayPort: 42,
					},
					BindOverlay: &RawAddr{
						Addr: "2001:db8::1",
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Prefer IPv6 to IPv4",
			Map: RawBRAddrMap{
				"IPv4": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "127.0.0.1",
						OverlayPort: 42,
					},
				},
				"IPv6": &RawOverlayBind{
					PublicOverlay: RawAddrOverlay{
						Addr:        "::1",
						OverlayPort: 73,
					},
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 73,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			topoBRAddr, err := tc.Map.ToUDPAddr()
			tc.ExpectedError(t, err)
			assert.Equal(t, tc.ExpectedAddress, topoBRAddr)
		})
	}
}

func TestExternalDataPlanePort(t *testing.T) {
	testCases := []struct {
		Name            string
		Raw             *RawBRIntf
		ExpectedAddress *net.UDPAddr
		ExpectedError   assert.ErrorAssertionFunc
	}{
		{
			Name:          "Empty",
			Raw:           &RawBRIntf{},
			ExpectedError: assert.Error,
		},
		{
			Name: "Empty with overlay",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv4",
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad IPv4 only",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv4",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "foo",
					OverlayPort: 42,
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv4 only",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv4",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "127.0.0.1",
					OverlayPort: 42,
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 1},
				Port: 42,
			},
		},
		{
			Name: "IPv4 contains IPv6",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv4",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "::1",
					OverlayPort: 42,
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv4 with bind underlay",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv4",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "127.0.0.1",
					OverlayPort: 42,
				},
				BindOverlay: &RawAddr{
					Addr: "127.255.255.255",
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.IP{127, 255, 255, 255},
				Port: 42,
			},
		},
		{
			Name: "IPv4 with bad underlay",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv4",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "127.0.0.1",
					OverlayPort: 42,
				},
				BindOverlay: &RawAddr{
					Addr: "foo",
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv4 with IPv6 underlay",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv4",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "127.0.0.1",
					OverlayPort: 42,
				},
				BindOverlay: &RawAddr{
					Addr: "::1",
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad IPv6 only",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv6",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "foo",
					OverlayPort: 42,
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv6 only",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv6",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "::1",
					OverlayPort: 42,
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 42,
			},
		},
		{
			Name: "IPv6 contains IPv4",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv6",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "127.0.0.1",
					OverlayPort: 42,
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv6 with bind underlay",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv6",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "::1",
					OverlayPort: 42,
				},
				BindOverlay: &RawAddr{
					Addr: "2001:db8::1",
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8::1"),
				Port: 42,
			},
		},
		{
			Name: "IPv6 with bad underlay",
			Raw: &RawBRIntf{
				Overlay: "UDP/IPv6",
				PublicOverlay: &RawAddrOverlay{
					Addr:        "::1",
					OverlayPort: 42,
				},
				BindOverlay: &RawAddr{
					Addr: "foo",
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv6 with IPv4 underlay",
			Raw: &RawBRIntf{
				PublicOverlay: &RawAddrOverlay{
					Addr:        "::1",
					OverlayPort: 42,
				},
				BindOverlay: &RawAddr{
					Addr: "127.0.0.1",
				},
			},
			ExpectedError: assert.Error,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			topoBRAddr, err := tc.Raw.TopoBRAddr()
			tc.ExpectedError(t, err)
			assert.Equal(t, tc.ExpectedAddress, topoBRAddr)
		})
	}
}

func MustLoadTopo(t *testing.T, filename string) *Topo {
	topo, err := LoadFromFile(filename)
	require.NoError(t, err, "Error loading config from '%s': %v", filename, err)
	return topo
}
