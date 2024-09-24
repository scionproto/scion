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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	jsontopo "github.com/scionproto/scion/private/topology/json"
)

func TestMeta(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")
	assert.Equal(t, time.Unix(168570123, 0), c.Timestamp, "Field 'Timestamp'")
	assert.Equal(t, addr.MustIAFrom(1, 0xff0000000311), c.IA, "Field 'ISD_AS'")
	assert.Equal(t, 1472, c.MTU, "Field 'MTU'")
	assert.False(t, c.IsCore, "Field 'Attributes'")
}

func TestActive(t *testing.T) {
	t.Run("positive TTL", func(t *testing.T) {
		c := MustLoadTopo(t, "testdata/basic.json")
		assert.False(t, c.Active(c.Timestamp.Add(-time.Second)))
		assert.True(t, c.Active(c.Timestamp))
		assert.False(t, c.Active(c.Timestamp.Add(-time.Hour)))
	})
	t.Run("zero TTL", func(t *testing.T) {
		c := MustLoadTopo(t, "testdata/basic.json")
		assert.False(t, c.Active(c.Timestamp.Add(-time.Second)))
		assert.True(t, c.Active(c.Timestamp))
		assert.True(t, c.Active(c.Timestamp.Add(100*time.Hour)))

	})
}

func TestBRs(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")

	brs := map[string]BRInfo{
		"br1-ff00:0:311-1": {
			IfIDs: []iface.ID{1, 3, 8},
		},
		"br1-ff00:0:311-2": {
			IfIDs: []iface.ID{11},
		},
	}

	for name, info := range brs {
		t.Run("checking BR details for "+name, func(t *testing.T) {
			for _, i := range info.IfIDs {
				assert.Contains(t, c.BR[name].IfIDs, i)
			}
		})
	}
	assert.Len(t, c.BR, 2)
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
		"cs1-ff00:0:311-4": TopoAddr{
			SCIONAddress: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:f00:b43::1"),
				Port: 23425,
				Zone: "some-zone",
			},
			UnderlayAddress: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:f00:b43::1"),
				Port: 30041,
				Zone: "some-zone",
			},
		},
	}
	assert.Equal(t, cses, c.CS)

	dses := IDAddrMap{
		"ds1-ff00:0:311-2": TopoAddr{
			SCIONAddress: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 67},
				Port: 30073,
			},
			UnderlayAddress: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 67},
				Port: 30041,
			},
		},
	}
	assert.Equal(t, dses, c.DS)

	sigs := map[string]GatewayInfo{
		"sig1-ff00:0:311-1": {
			CtrlAddr: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.IP{127, 0, 0, 82},
					Port: 30100,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.IP{127, 0, 0, 82},
					Port: 30041,
				},
			},
			DataAddr: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 82},
				Port: 30101,
			},
			ProbeAddr: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 82},
				Port: 30856,
			},
			AllowInterfaces: []uint64{1, 3, 5},
		},
		"sig2-ff00:0:311-1": {
			CtrlAddr: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 23425,
					Zone: "some-zone",
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 30041,
					Zone: "some-zone",
				},
			},
			DataAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:f00:b43::1"),
				Port: 30101,
				Zone: "some-zone",
			},
			ProbeAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:f00:b43::2"),
				Port: 23455,
				Zone: "some-zone",
			},
		},
	}
	assert.Equal(t, sigs, c.SIG)

}

func TestServiceCount(t *testing.T) {
	// This just checks the count of all the service types, actual population
	// testing is done elsewhere
	// The simple counting check for CS is done in the detailed population test as well
	c := MustLoadTopo(t, "testdata/basic.json")
	assert.Len(t, c.CS, 3, "CS")
	assert.Len(t, c.DS, 1, "DS")
	assert.Len(t, c.SIG, 2, "SIG")
}

func TestIFInfoMap(t *testing.T) {
	c := MustLoadTopo(t, "testdata/basic.json")
	ifm := IfInfoMap{
		1: IFInfo{
			ID:           1,
			BRName:       "br1-ff00:0:311-1",
			InternalAddr: netip.MustParseAddrPort("10.1.0.1:0"),
			Local:        netip.MustParseAddrPort("192.0.2.1:44997"),
			Remote:       netip.MustParseAddrPort("192.0.2.2:44998"),
			IA:           addr.MustParseIA("1-ff00:0:312"),
			LinkType:     Parent,
			MTU:          1472,
			BFD: BFD{
				DetectMult:            10,
				DesiredMinTxInterval:  10 * time.Millisecond,
				RequiredMinRxInterval: 15 * time.Millisecond,
			},
		},
		3: IFInfo{
			ID:           3,
			BRName:       "br1-ff00:0:311-1",
			InternalAddr: netip.MustParseAddrPort("10.1.0.1:0"),
			Local:        netip.MustParseAddrPort("[2001:db8:a0b:12f0::1]:44997"),
			Remote:       netip.MustParseAddrPort("[2001:db8:a0b:12f0::2]:44998"),
			IA:           addr.MustParseIA("1-ff00:0:314"),
			LinkType:     Child,
			MTU:          4430,
		},
		8: IFInfo{
			ID:           8,
			BRName:       "br1-ff00:0:311-1",
			InternalAddr: netip.MustParseAddrPort("10.1.0.1:0"),
			Local:        netip.AddrPortFrom(netip.Addr{}, 44997),
			Remote:       netip.MustParseAddrPort("192.0.2.3:44998"),
			IA:           addr.MustParseIA("1-ff00:0:313"),
			LinkType:     Peer,
			MTU:          1480,
		},
		11: IFInfo{
			ID:           11,
			BRName:       "br1-ff00:0:311-2",
			InternalAddr: netip.MustParseAddrPort(`[2001:db8:a0b:12f0::1%some-internal-zone]:0`),
			Local:        netip.MustParseAddrPort(`[2001:db8:a0b:12f0::1%some-local-zone]:44897`),
			Remote:       netip.MustParseAddrPort(`[2001:db8:a0b:12f0::2%some-remote-zone]:44898`),
			IA:           addr.MustParseIA("1-ff00:0:314"),
			LinkType:     Child,
			MTU:          4430,
		},
	}
	assert.Equal(t, ifm, c.IFInfoMap)
}

func TestIFInfoMapDeprecatedPublicBind(t *testing.T) {
	c := MustLoadTopo(t, "testdata/deprecated-public-bind.json")
	ifm := IfInfoMap{
		// local: bind IP, public port
		1: IFInfo{
			ID:           1,
			BRName:       "br1-ff00:0:311-1",
			InternalAddr: netip.MustParseAddrPort("10.1.0.1:0"),
			Local:        netip.MustParseAddrPort("10.0.0.1:44997"),
			Remote:       netip.MustParseAddrPort("192.0.2.2:44998"),
			IA:           addr.MustParseIA("1-ff00:0:312"),
			LinkType:     Parent,
			MTU:          1472,
		},
		// local: bind IP, public port
		3: IFInfo{
			ID:           3,
			BRName:       "br1-ff00:0:311-1",
			InternalAddr: netip.MustParseAddrPort("10.1.0.1:0"),
			Local:        netip.MustParseAddrPort("[2001:db8:a0b:12f0::8]:44997"),
			Remote:       netip.MustParseAddrPort("[2001:db8:a0b:12f0::2]:44998"),
			IA:           addr.MustParseIA("1-ff00:0:314"),
			LinkType:     Child,
			MTU:          4430,
		},
		// local: public, no bind
		8: IFInfo{
			ID:           8,
			BRName:       "br1-ff00:0:311-1",
			InternalAddr: netip.MustParseAddrPort("10.1.0.1:0"),
			Local:        netip.MustParseAddrPort("192.0.2.2:44997"),
			Remote:       netip.MustParseAddrPort("192.0.2.3:44998"),
			IA:           addr.MustParseIA("1-ff00:0:313"),
			LinkType:     Peer,
			MTU:          1480,
		},
	}
	assert.Equal(t, ifm, c.IFInfoMap)
}

func TestIFInfoMapCoreAS(t *testing.T) {

	c := MustLoadTopo(t, "testdata/core.json")
	ifm := IfInfoMap{
		91: IFInfo{
			ID:           91,
			BRName:       "borderrouter6-ff00:0:362-1",
			InternalAddr: netip.MustParseAddrPort("10.1.0.1:0"),
			Local:        netip.MustParseAddrPort("192.0.2.1:4997"),
			Remote:       netip.MustParseAddrPort("192.0.2.2:4998"),
			IA:           addr.MustParseIA("6-ff00:0:363"),
			LinkType:     Core,
			MTU:          1472,
		},
		32: IFInfo{
			ID:           32,
			BRName:       "borderrouter6-ff00:0:362-9",
			InternalAddr: netip.MustParseAddrPort("[2001:db8:a0b:12f0::2]:0"),
			Local:        netip.MustParseAddrPort("[2001:db8:a0b:12f0::1]:4997"),
			Remote:       netip.MustParseAddrPort("[2001:db8:a0b:12f0::2]:4998"),
			IA:           addr.MustParseIA("6-ff00:0:364"),
			LinkType:     Child,
			MTU:          4430,
		},
	}
	assert.Equal(t, ifm, c.IFInfoMap)
}

func TestBRsCoreAS(t *testing.T) {
	c := MustLoadTopo(t, "testdata/core.json")
	brCases := []struct {
		name       string
		interfaces []iface.ID
	}{
		{name: "borderrouter6-ff00:0:362-1", interfaces: []iface.ID{91}},
		{name: "borderrouter6-ff00:0:362-9", interfaces: []iface.ID{32}},
	}
	for _, test := range brCases {
		t.Run(test.name, func(t *testing.T) {
			assert.Contains(t, c.BR, test.name)
			for _, intf := range test.interfaces {
				assert.Contains(t, c.BR[test.name].IfIDs, intf)
			}
		})
	}
	assert.Equal(t, len(c.BR), len(brCases), "Mismatched number of BRs")
}

func TestCopy(t *testing.T) {
	topo, err := RWTopologyFromJSONFile("testdata/core.json")
	require.NoError(t, err)

	newTopo := topo.Copy()
	assert.Equal(t, topo.BR, newTopo.BR)
	assert.Equal(t, topo, newTopo)
}

func TestExternalDataPlanePort(t *testing.T) {
	testCases := []struct {
		Name            string
		Raw             *jsontopo.Underlay
		ExpectedAddress netip.AddrPort
		ExpectedError   assert.ErrorAssertionFunc
	}{
		{
			Name:          "Empty",
			Raw:           &jsontopo.Underlay{},
			ExpectedError: assert.Error,
		},
		{
			Name: "Port only",
			Raw: &jsontopo.Underlay{
				Local: ":42",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.AddrPortFrom(netip.Addr{}, 42),
		},
		{
			Name: "Good IPv4",
			Raw: &jsontopo.Underlay{
				Local: "127.0.0.1:42",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort("127.0.0.1:42"),
		},
		{
			Name: "Good IPv6",
			Raw: &jsontopo.Underlay{
				Local: "[::1]:42",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort("[::1]:42"),
		},
		{
			Name: "Good IPv6 with zone",
			Raw: &jsontopo.Underlay{
				Local: "[::1%some-zone]:42",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort(`[::1%some-zone]:42`),
		},
		// Deprecated Public / Bind
		{
			Name: "Both deprecated public and local",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "something:42",
				Local:            "fnord:99",
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Deprecated Bad invalid public",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "thishostdoesnotexist:42",
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Deprecated Good IPv4 only",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "127.0.0.1:42",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort("127.0.0.1:42"),
		},
		{
			Name: "Deprecated IPv4 with bind underlay",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "127.0.0.1:42",
				DeprecatedBind:   "127.255.255.255",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort("127.255.255.255:42"),
		},
		{
			Name: "Deprecated IPv4 with bad bind",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "127.0.0.1:42",
				DeprecatedBind:   "thishostdoesnotexist",
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Deprecated Good IPv6 only",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "[::1]:42",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort("[::1]:42"),
		},
		{
			Name: "Deprecated Good IPv6 only with zone",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "[::1%some-zone]:42",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort(`[::1%some-zone]:42`),
		},
		{
			Name: "Deprecated IPv6 with bind underlay",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "[::1]:42",
				DeprecatedBind:   "2001:db8::1",
			},
			ExpectedError:   assert.NoError,
			ExpectedAddress: netip.MustParseAddrPort(`[2001:db8::1]:42`),
		},
		{
			Name: "Deprecated IPv6 with bad bind underlay",
			Raw: &jsontopo.Underlay{
				DeprecatedPublic: "[::1]:42",
				DeprecatedBind:   "thishostdoesnotexist",
			},
			ExpectedError: assert.Error,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			topoBRAddr, err := RawBRIntfLocalAddr(tc.Raw)
			tc.ExpectedError(t, err)
			assert.Equal(t, tc.ExpectedAddress, topoBRAddr)
		})
	}
}

func TestRawAddrMap_ToTopoAddr(t *testing.T) {
	testCases := []struct {
		name        string
		assertError assert.ErrorAssertionFunc
		raw         string
		addr        *TopoAddr
	}{
		{
			name:        "No addresses",
			assertError: assert.Error,
			raw:         "",
		},
		{
			name:        "IPvX invalid address",
			assertError: assert.Error,
			raw:         "thishostdoesnotexist:42",
		},
		{
			name:        "IPv4 invalid port",
			assertError: assert.Error,
			raw:         "127.0.0.1:bar",
		},
		{
			name:        "IPv4 good address",
			assertError: assert.NoError,
			raw:         "192.168.1.1:42",
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
			name:        "IPv6 good address with zone",
			assertError: assert.NoError,
			raw:         "[2001:db8:f00:b43::1%some-zone]:42",
			addr: &TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 42,
					Zone: "some-zone",
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.ParseIP("2001:db8:f00:b43::1"),
					Port: 30041,
					Zone: "some-zone",
				},
			},
		},
		{
			name:        "IPv6",
			assertError: assert.NoError,
			raw:         "[2001:db8:f00:b43::1]:42",
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
			// topoAddr, err := RawAddrToTopoAddr(tc.raw)
			// tc.assertError(t, err)
			// assert.Equal(t, tc.addr, topoAddr)
		})
	}
}

func TestServiceNamesGetRandom(t *testing.T) {
	names := ServiceNames(nil)
	name, err := names.GetRandom()
	assert.Error(t, err)
	assert.Empty(t, name)
}

func MustLoadTopo(t *testing.T, filename string) *RWTopology {
	topo, err := RWTopologyFromJSONFile(filename)
	require.NoError(t, err, "Error loading config from '%s': %v", filename, err)
	return topo
}
