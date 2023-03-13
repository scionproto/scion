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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/xtest"
	jsontopo "github.com/scionproto/scion/private/topology/json"
	"github.com/scionproto/scion/private/topology/underlay"
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
			IFIDs: []common.IFIDType{1, 3, 8},
		},
		"br1-ff00:0:311-2": {
			IFIDs: []common.IFIDType{11},
		},
	}
	brn := []string{"br1-ff00:0:311-1", "br1-ff00:0:311-2"}

	for name, info := range brs {
		t.Run("checking BR details for "+name, func(t *testing.T) {
			for _, i := range info.IFIDs {
				assert.Contains(t, c.BR[name].IFIDs, i)
			}
			assert.ElementsMatch(t, c.BRNames, brn)
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
			ID:     1,
			BRName: "br1-ff00:0:311-1",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("10.1.0.1").To4(),
				Port: 0,
			},
			Underlay: underlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 1}.To4(),
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 2}.To4(),
				Port: 44998,
			},
			IA:       xtest.MustParseIA("1-ff00:0:312"),
			LinkType: Parent,
			MTU:      1472,
			BFD: BFD{
				DetectMult:            10,
				DesiredMinTxInterval:  10 * time.Millisecond,
				RequiredMinRxInterval: 15 * time.Millisecond,
			},
		},
		3: IFInfo{
			ID:     3,
			BRName: "br1-ff00:0:311-1",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("10.1.0.1").To4(),
				Port: 0,
			},
			Underlay: underlay.UDPIPv6,
			Local: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::8"),
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 44998,
			},
			IA:       xtest.MustParseIA("1-ff00:0:314"),
			LinkType: Child,
			MTU:      4430,
		},
		8: IFInfo{
			ID:     8,
			BRName: "br1-ff00:0:311-1",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("10.1.0.1").To4(),
				Port: 0,
			},
			Underlay: underlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 2}.To4(),
				Port: 44997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 3}.To4(),
				Port: 44998,
			},
			IA:       xtest.MustParseIA("1-ff00:0:313"),
			LinkType: Peer,
			MTU:      1480,
		},
		11: IFInfo{
			ID:     11,
			BRName: "br1-ff00:0:311-2",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::1"),
				Port: 0,
				Zone: "some-internal-zone",
			},
			Underlay: underlay.UDPIPv6,
			Local: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::8"),
				Port: 44897,
				Zone: "some-bind-zone",
			},
			Remote: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 44898,
				Zone: "some-remote-zone",
			},
			IA:       xtest.MustParseIA("1-ff00:0:314"),
			LinkType: Child,
			MTU:      4430,
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
				IP:   net.ParseIP("10.1.0.1").To4(),
				Port: 0,
			},
			Underlay: underlay.UDPIPv4,
			Local: &net.UDPAddr{
				IP:   net.IP{10, 0, 0, 1}.To4(),
				Port: 4997,
			},
			Remote: &net.UDPAddr{
				IP:   net.IP{192, 0, 2, 2}.To4(),
				Port: 4998,
			},
			IA:       xtest.MustParseIA("6-ff00:0:363"),
			LinkType: Core,
			MTU:      1472,
		},
		32: IFInfo{
			ID:     32,
			BRName: "borderrouter6-ff00:0:362-9",
			InternalAddr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 0,
			},
			Underlay: underlay.UDPIPv6,
			Local: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::8"),
				Port: 4997,
			},
			Remote: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8:a0b:12f0::2"),
				Port: 4998,
			},
			IA:       xtest.MustParseIA("6-ff00:0:364"),
			LinkType: Child,
			MTU:      4430,
		},
	}
	assert.Equal(t, ifm, c.IFInfoMap)
}

func TestBRsCoreAS(t *testing.T) {
	c := MustLoadTopo(t, "testdata/core.json")
	brCases := []struct {
		name       string
		interfaces []common.IFIDType
	}{
		{name: "borderrouter6-ff00:0:362-1", interfaces: []common.IFIDType{91}},
		{name: "borderrouter6-ff00:0:362-9", interfaces: []common.IFIDType{32}},
	}
	for _, test := range brCases {
		t.Run(test.name, func(t *testing.T) {
			assert.Contains(t, c.BR, test.name)
			for _, intf := range test.interfaces {
				assert.Contains(t, c.BR[test.name].IFIDs, intf)
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
			Name: "Empty with underlay",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Bad invalid public",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{
					Public: "thishostdoesnotexist:42",
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv4 only",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{
					Public: "127.0.0.1:42",
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.IP{127, 0, 0, 1},
				Port: 42,
			},
		},
		{
			Name: "IPv4 with bind underlay",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{
					Public: "127.0.0.1:42",
					Bind:   "127.255.255.255",
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.IP{127, 255, 255, 255},
				Port: 42,
			},
		},
		{
			Name: "IPv4 with bad bind",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{
					Public: "127.0.0.1:42",
					Bind:   "thishostdoesnotexist",
				},
			},
			ExpectedError: assert.Error,
		},
		{
			Name: "Good IPv6 only",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{
					Public: "[::1]:42",
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 42,
			},
		},
		{
			Name: "Good IPv6 only with zone",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{
					Public: "[::1%some-zone]:42",
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 42,
				Zone: "some-zone",
			},
		},
		{
			Name: "IPv6 with bind underlay",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{
					Public: "[::1]:42",
					Bind:   "2001:db8::1",
				},
			},
			ExpectedError: assert.NoError,
			ExpectedAddress: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8::1"),
				Port: 42,
			},
		},
		{
			Name: "IPv6 with bad bind underlay",
			Raw: &jsontopo.BRInterface{
				Underlay: jsontopo.Underlay{
					Public: "[::1]:42",
					Bind:   "thishostdoesnotexist",
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
			topoAddr, err := RawAddrToTopoAddr(tc.raw)
			tc.assertError(t, err)
			assert.Equal(t, tc.addr, topoAddr)
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
