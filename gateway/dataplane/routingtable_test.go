// Copyright 2020 Anapaya Systems
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

package dataplane_test

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/dataplane"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestRoutingTable(t *testing.T) {
	rt := &dataplane.RoutingTable{}
	_, ok := any(rt).(control.RoutingTable)
	if ok != true {
		assert.Fail(t, "should implement the client interface")
	}
}

func TestRoutingTableRouteIPv4(t *testing.T) {
	testCases := map[string]struct {
		rt    func() *dataplane.RoutingTable
		input []layers.IPv4
		want  []control.PktWriter
	}{
		"table is empty": {
			rt: func() *dataplane.RoutingTable {
				return dataplane.NewRoutingTable(nil)
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{nil},
		},
		"none up": {
			rt: func() *dataplane.RoutingTable {
				return dataplane.NewRoutingTable([]*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondTrue},
						},
					},
				})
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{nil},
		},
		"no matching class": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable([]*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondFalse},
						},
					},
				})
				require.NoError(t, rt.SetSession(1, testPktWriter{}))
				return rt
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{nil},
		},
		"match on condition": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable([]*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondFalse},
							{ID: 2, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.SetSession(2, testPktWriter{}))
				return rt
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{testPktWriter{}},
		},
		"match on longest prefix": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable([]*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/16")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondTrue},
						},
					},
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 2, Matcher: pktcls.CondTrue},
						},
					},
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/8")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 3, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.SetSession(2, testPktWriter{}))
				return rt
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{testPktWriter{}},
		},
		"no match on prefix": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable([]*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.0.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.SetSession(1, testPktWriter{}))
				return rt
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{nil},
		},
		"match both": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable([]*control.RoutingChain{
					{
						Prefixes: xtest.MustParseCIDRs(t, "192.168.100.0/24", "10.2.0.0/24"),
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.SetSession(1, testPktWriter{ID: 1}))
				return rt
			},
			input: []layers.IPv4{
				{DstIP: net.IP{192, 168, 100, 2}},
				{DstIP: net.IP{10, 2, 0, 2}},
			},
			want: []control.PktWriter{
				testPktWriter{ID: 1},
				testPktWriter{ID: 1},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for i, input := range tc.input {
				i, input := i, input
				t.Run(strconv.Itoa(i), func(t *testing.T) {
					t.Parallel()
					got := tc.rt().RouteIPv4(input)
					assert.Equal(t, tc.want[i], got)
				})
			}
		})
	}
}

func TestRoutingTableRouteIPv6(t *testing.T) {
	testCases := map[string]struct {
		rt    func() *dataplane.RoutingTable
		input layers.IPv6
		want  control.PktWriter
	}{
		"match on condition": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable([]*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "2001:db8:a0b:12f0::1/32")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondFalse},
							{ID: 2, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.SetSession(2, testPktWriter{}))
				return rt
			},
			input: layers.IPv6{DstIP: net.ParseIP("2001:db8:a0b:12f0::1")},
			want:  testPktWriter{},
		},
		"match on longest prefix": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable([]*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "2001:db8:a0b:12f0::1/64")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondTrue},
						},
					},
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "2001:db8:a0b:12f0::1/96")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 2, Matcher: pktcls.CondTrue},
						},
					},
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "2001:db8:a0b:12f0::1/32")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 3, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.SetSession(2, testPktWriter{}))
				return rt
			},
			input: layers.IPv6{DstIP: net.ParseIP("2001:db8:a0b:12f0::1")},
			want:  testPktWriter{},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := tc.rt().RouteIPv6(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRoutingTableAddClearSession(t *testing.T) {
	buildRT := func() *dataplane.RoutingTable {
		return dataplane.NewRoutingTable([]*control.RoutingChain{
			{
				Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/16")},
				TrafficMatchers: []control.TrafficMatcher{
					{ID: 1, Matcher: pktcls.CondTrue},
				},
			},
			{
				Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/24")},
				TrafficMatchers: []control.TrafficMatcher{
					{ID: 2, Matcher: pktcls.CondTrue},
				},
			},
		})
	}
	testCases := map[string]func(t *testing.T){
		"add nil session errors": func(t *testing.T) {
			assert.Error(t, buildRT().SetSession(2, nil))
		},
		"add invalid index errors": func(t *testing.T) {
			assert.Error(t, buildRT().SetSession(5, testPktWriter{}))
		},
		"delete invalid index errors": func(t *testing.T) {
			assert.Error(t, buildRT().ClearSession(5))
		},
		"delete non-set session": func(t *testing.T) {
			assert.NoError(t, buildRT().ClearSession(2))
		},
		"adding a session works correctly": func(t *testing.T) {
			rt := buildRT()
			assert.NoError(t, rt.SetSession(2, testPktWriter{ID: 2}))
			sess := rt.RouteIPv4(layers.IPv4{DstIP: net.ParseIP("192.168.100.2")})
			assert.Equal(t, testPktWriter{ID: 2}, sess)
			// now override
			assert.NoError(t, rt.SetSession(2, testPktWriter{ID: 5}))
			sess = rt.RouteIPv4(layers.IPv4{DstIP: net.ParseIP("192.168.100.2")})
			assert.Equal(t, testPktWriter{ID: 5}, sess)
		},
		"deleting a session works correctly": func(t *testing.T) {
			rt := buildRT()
			assert.NoError(t, rt.SetSession(2, testPktWriter{ID: 2}))
			sess := rt.RouteIPv4(layers.IPv4{DstIP: net.ParseIP("192.168.100.2")})
			assert.Equal(t, testPktWriter{ID: 2}, sess)
			assert.NoError(t, rt.ClearSession(2))
			assert.Nil(t, rt.RouteIPv4(layers.IPv4{DstIP: net.ParseIP("192.168.100.2")}))
		},
	}
	for name, tc := range testCases {
		t.Run(name, tc)
	}
}

type testPktWriter struct {
	ID int
}

func (_ testPktWriter) Write(gopacket.Packet) {}
func (w testPktWriter) String() string {
	return fmt.Sprintf("%d", w.ID)
}
