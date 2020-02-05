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
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	jsontopo "github.com/scionproto/scion/go/lib/topology/json"
	"github.com/scionproto/scion/go/lib/topology/overlay"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestMeta(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")
	assert.Equal(t, time.Unix(168570123, 0), c.Timestamp, "Field 'Timestamp'")
	assert.Equal(t, time.Hour, c.TTL, "Field 'TTL'")
	assert.Equal(t, addr.IA{I: 1, A: 0xff0000000311}, c.IA, "Field 'ISD_AS'")
	assert.Equal(t, 1472, c.MTU, "Field 'MTU'")
	assert.Empty(t, c.Attributes, "Field 'Attributes'")
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
			SCIONAddress: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 67},
				Port: 30073,
			},
			UnderlayAddress: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 67},
				Port: 30041,
			},
		},
		"cs1-ff00:0:311-3": TopoAddr{
			SCIONAddress: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:f00:b43::1"),
				Port: 23421,
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
	assert.Len(t, c.CS, 2, "CS")
	assert.Len(t, c.SIG, 2, "SIG")
}

func TestIFInfoMap(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")
	ifm := IfInfoMap{
		1: IFInfo{
			ID:     1,
			BRName: "br1-ff00:0:311-1",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
					Port: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::1"), Port: 30041},
			},
			Underlay: overlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 1},
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 2},
				Port: 44998,
			},
			Bandwidth: 1000,
			IA:        xtest.MustParseIA("1-ff00:0:312"),
			LinkType:  Parent,
			MTU:       1472,
		},
		3: IFInfo{
			ID:     3,
			BRName: "br1-ff00:0:311-1",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
					Port: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::1"), Port: 30041},
			},
			Underlay: overlay.UDPIPv6,
			Local: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::8"),
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 44998,
			},
			Bandwidth: 5000,
			IA:        xtest.MustParseIA("1-ff00:0:314"),
			LinkType:  Child,
			MTU:       4430,
		},
		8: IFInfo{
			ID:     8,
			BRName: "br1-ff00:0:311-1",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
					Port: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::1"), Port: 30041},
			},
			Underlay: overlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 2},
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 3},
				Port: 44998,
			},
			Bandwidth: 2000,
			IA:        xtest.MustParseIA("1-ff00:0:313"),
			LinkType:  Peer,
			MTU:       1480,
		},
	}
	assert.Equal(t, ifm, c.IFInfoMap)
}

func TestIFInfoMapCoreAS(t *testing.T) {
	c := MustLoadTopo(t, "testdata/core.json")
	ifm := IfInfoMap{
		91: IFInfo{
			ID:     91,
			BRName: "borderrouter6-ff00:0:362-1",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
					Port: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::1"), Port: 30041},
			},
			Underlay: overlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 1},
				Port: 4997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 2},
				Port: 4998,
			},
			Bandwidth: 100000,
			IA:        xtest.MustParseIA("6-ff00:0:363"),
			LinkType:  Core,
			MTU:       1472,
		},
		32: IFInfo{
			ID:     32,
			BRName: "borderrouter6-ff00:0:362-9",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 0,
			},
			CtrlAddrs: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
					Port: 30098,
				},
				UnderlayAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8:a0b:12f0::2"), Port: 30041},
			},
			Underlay: overlay.UDPIPv6,
			Local: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::8"),
				Port: 4997,
			},
			Remote: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 4998,
			},
			Bandwidth: 5000,
			IA:        xtest.MustParseIA("6-ff00:0:364"),
			LinkType:  Child,
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

func TestInternalDataPlanePort(t *testing.T) {
	testCases := []struct {
		Name            string
		Map             jsontopo.UnderlayAddressMap
		ExpectedAddress *net.UDPAddr
		ExpectedError   assert.ErrorAssertionFunc
	}{
		{
			Name:          "Empty",
			Map:           jsontopo.UnderlayAddressMap{},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad IPv4 only",
			Map: jsontopo.UnderlayAddressMap{
				"IPv4": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "foo",
						UnderlayPort: 42,
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv4 only",
			Map: jsontopo.UnderlayAddressMap{
				"IPv4": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "127.0.0.1",
						UnderlayPort: 42,
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
			Map: jsontopo.UnderlayAddressMap{
				"IPv4": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "::1",
						UnderlayPort: 42,
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv4 with bind underlay",
			Map: jsontopo.UnderlayAddressMap{
				"IPv4": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "127.0.0.1",
						UnderlayPort: 42,
					},
					BindUnderlay: &jsontopo.L3Address{
						Addr: "127.255.255.255",
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad IPv6 only",
			Map: jsontopo.UnderlayAddressMap{
				"IPv6": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "foo",
						UnderlayPort: 42,
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv6 only",
			Map: jsontopo.UnderlayAddressMap{
				"IPv6": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "::1",
						UnderlayPort: 42,
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
			Map: jsontopo.UnderlayAddressMap{
				"IPv6": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "127.0.0.1",
						UnderlayPort: 42,
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv6 with bind underlay",
			Map: jsontopo.UnderlayAddressMap{
				"IPv6": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "::1",
						UnderlayPort: 42,
					},
					BindUnderlay: &jsontopo.L3Address{
						Addr: "2001:db8::1",
					},
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Prefer IPv6 to IPv4",
			Map: jsontopo.UnderlayAddressMap{
				"IPv4": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "127.0.0.1",
						UnderlayPort: 42,
					},
				},
				"IPv6": &jsontopo.NATUnderlayAddress{
					PublicUnderlay: jsontopo.UnderlayAddress{
						Addr:         "::1",
						UnderlayPort: 73,
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
			topoBRAddr, err := RawBRAddrMapToUDPAddr(tc.Map)
			tc.ExpectedError(t, err)
			assert.Equal(t, tc.ExpectedAddress, topoBRAddr)
		})
	}
}

func TestExternalDataPlanePort(t *testing.T) {
	testCases := []struct {
		Name            string
		Raw             *jsontopo.BRInterface
		ExpectedAddress *net.UDPAddr
		ExpectedError   assert.ErrorAssertionFunc
	}{
		{
			Name:          "Empty",
			Raw:           &jsontopo.BRInterface{},
			ExpectedError: assert.Error,
		},
		{
			Name: "Empty with overlay",
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv4",
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad IPv4 only",
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv4",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "foo",
					UnderlayPort: 42,
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv4 only",
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv4",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "127.0.0.1",
					UnderlayPort: 42,
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
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv4",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "::1",
					UnderlayPort: 42,
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv4 with bind underlay",
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv4",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "127.0.0.1",
					UnderlayPort: 42,
				},
				BindUnderlay: &jsontopo.L3Address{
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
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv4",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "127.0.0.1",
					UnderlayPort: 42,
				},
				BindUnderlay: &jsontopo.L3Address{
					Addr: "foo",
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv4 with IPv6 underlay",
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv4",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "127.0.0.1",
					UnderlayPort: 42,
				},
				BindUnderlay: &jsontopo.L3Address{
					Addr: "::1",
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad IPv6 only",
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv6",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "foo",
					UnderlayPort: 42,
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv6 only",
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv6",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "::1",
					UnderlayPort: 42,
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
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv6",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "127.0.0.1",
					UnderlayPort: 42,
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv6 with bind underlay",
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv6",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "::1",
					UnderlayPort: 42,
				},
				BindUnderlay: &jsontopo.L3Address{
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
			Raw: &jsontopo.BRInterface{
				Underlay: "UDP/IPv6",
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "::1",
					UnderlayPort: 42,
				},
				BindUnderlay: &jsontopo.L3Address{
					Addr: "foo",
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "IPv6 with IPv4 underlay",
			Raw: &jsontopo.BRInterface{
				PublicUnderlay: &jsontopo.UnderlayAddress{
					Addr:         "::1",
					UnderlayPort: 42,
				},
				BindUnderlay: &jsontopo.L3Address{
					Addr: "127.0.0.1",
				},
			},
			ExpectedError: assert.Error,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			topoBRAddr, err := RawBRIntfTopoBRAddr(tc.Raw)
			tc.ExpectedError(t, err)
			assert.Equal(t, tc.ExpectedAddress, topoBRAddr)
		})
	}
}

func TestRawAddrMap_ToTopoAddr(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		ram  jsontopo.NATSCIONAddressMap
		addr *TopoAddr
	}{
		{
			name: "No addresses",
			err:  errAtLeastOnePub,
			ram:  make(jsontopo.NATSCIONAddressMap),
			addr: nil,
		},
		{
			name: "IPv4 invalid address",
			err:  errInvalidPub,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv4": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "foo",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 empty address",
			err:  errInvalidPub,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv4": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 address in IPv4 property",
			err:  errInvalidPub,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv4": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 address in IPv6 property",
			err:  errInvalidPub,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv6": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 invalid address",
			err:  errInvalidPub,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv6": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "foo",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 empty address",
			err:  errInvalidPub,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv6": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "",
							L4Port: 42,
						},
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 good address",
			ram: jsontopo.NATSCIONAddressMap{
				"IPv4": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
					},
				},
			},
			addr: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.IP{192, 168, 1, 1},
					Port: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.IP{192, 168, 1, 1},
					Port: 30041,
				},
			},
		},
		{
			name: "IPv6 good address",
			ram: jsontopo.NATSCIONAddressMap{
				"IPv6": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
					},
				},
			},
			addr: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 30041,
				},
			},
		},
		{
			name: "IPv4 with bind",
			err:  errBindNotSupported,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv4": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
					},
					Bind: &jsontopo.Address{},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 with bind",
			err:  errBindNotSupported,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv6": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
					},
					Bind: &jsontopo.Address{},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 with custom underlay",
			err:  errCustomUnderlayPort,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv4": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
						UnderlayPort: 73,
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv6 with custom underlay",
			err:  errCustomUnderlayPort,
			ram: jsontopo.NATSCIONAddressMap{
				"IPv6": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
						UnderlayPort: 73,
					},
				},
			},
			addr: nil,
		},
		{
			name: "IPv4 with IPv6",
			ram: jsontopo.NATSCIONAddressMap{
				"IPv4": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "192.168.1.1",
							L4Port: 42,
						},
					},
				},
				"IPv6": &jsontopo.NATSCIONAddress{
					Public: jsontopo.FullSCIONAddress{
						Address: jsontopo.Address{
							Addr:   "2001:db8:f00:b43::1",
							L4Port: 42,
						},
					},
				},
			},
			addr: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 30041,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			topoAddr, err := RawAddrMapToTopoAddr(tc.ram)
			xtest.AssertErrorsIs(t, err, tc.err)
			if tc.err == nil {
				assert.Equal(t, tc.addr, topoAddr)
			}
		})
	}
}

func MustLoadTopo(t *testing.T, filename string) *RWTopology {
	topo, err := RWTopologyFromJSONFile(filename)
	require.NoError(t, err, "Error loading config from '%s': %v", filename, err)
	return topo
}
