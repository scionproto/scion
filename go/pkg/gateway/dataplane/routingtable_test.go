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

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
	"github.com/scionproto/scion/go/pkg/gateway/dataplane"
)

func TestRoutingTable(t *testing.T) {
	var rt interface{}
	rt = &dataplane.RoutingTable{}
	_, ok := rt.(control.RoutingTable)
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
			rt:    func() *dataplane.RoutingTable { return dataplane.NewRoutingTable(nil, nil) },
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{nil},
		},
		"none up": {
			rt: func() *dataplane.RoutingTable {
				return dataplane.NewRoutingTable(nil, []*control.RoutingChain{
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
				rt := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondFalse},
						},
					},
				})
				require.NoError(t, rt.AddRoute(1, testPktWriter{}))
				return rt
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{nil},
		},
		"match on condition": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondFalse},
							{ID: 2, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.AddRoute(2, testPktWriter{}))
				return rt
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{testPktWriter{}},
		},
		"match on longest prefix": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
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
				require.NoError(t, rt.AddRoute(2, testPktWriter{}))
				return rt
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{testPktWriter{}},
		},
		"no match on prefix": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.0.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.AddRoute(1, testPktWriter{}))
				return rt
			},
			input: []layers.IPv4{{DstIP: net.IP{192, 168, 100, 2}}},
			want:  []control.PktWriter{nil},
		},
		"match both": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
					{
						Prefixes: xtest.MustParseCIDRs(t, "192.168.100.0/24", "10.2.0.0/24"),
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.AddRoute(1, testPktWriter{ID: 1}))
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
				rt := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "2001:db8:a0b:12f0::1/32")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.CondFalse},
							{ID: 2, Matcher: pktcls.CondTrue},
						},
					},
				})
				require.NoError(t, rt.AddRoute(2, testPktWriter{}))
				return rt
			},
			input: layers.IPv6{DstIP: net.ParseIP("2001:db8:a0b:12f0::1")},
			want:  testPktWriter{},
		},
		"match on longest prefix": {
			rt: func() *dataplane.RoutingTable {
				rt := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
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
				require.NoError(t, rt.AddRoute(2, testPktWriter{}))
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

func TestRoutingTableAddDelRoute(t *testing.T) {
	buildRT := func() *dataplane.RoutingTable {
		return dataplane.NewRoutingTable(nil, []*control.RoutingChain{
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
			assert.Error(t, buildRT().AddRoute(2, nil))
		},
		"add invalid index errors": func(t *testing.T) {
			assert.Error(t, buildRT().AddRoute(5, testPktWriter{}))
		},
		"delete invalid index errors": func(t *testing.T) {
			assert.Error(t, buildRT().DelRoute(5))
		},
		"delete non-set session": func(t *testing.T) {
			assert.NoError(t, buildRT().DelRoute(2))
		},
		"adding a session works correctly": func(t *testing.T) {
			rt := buildRT()
			assert.NoError(t, rt.AddRoute(2, testPktWriter{ID: 2}))
			sess := rt.RouteIPv4(layers.IPv4{DstIP: net.ParseIP("192.168.100.2")})
			assert.Equal(t, testPktWriter{ID: 2}, sess)
			// now override
			assert.NoError(t, rt.AddRoute(2, testPktWriter{ID: 5}))
			sess = rt.RouteIPv4(layers.IPv4{DstIP: net.ParseIP("192.168.100.2")})
			assert.Equal(t, testPktWriter{ID: 5}, sess)
		},
		"deleting a session works correctly": func(t *testing.T) {
			rt := buildRT()
			assert.NoError(t, rt.AddRoute(2, testPktWriter{ID: 2}))
			sess := rt.RouteIPv4(layers.IPv4{DstIP: net.ParseIP("192.168.100.2")})
			assert.Equal(t, testPktWriter{ID: 2}, sess)
			assert.NoError(t, rt.DelRoute(2))
			assert.Nil(t, rt.RouteIPv4(layers.IPv4{DstIP: net.ParseIP("192.168.100.2")}))
		},
	}
	for name, tc := range testCases {
		t.Run(name, tc)
	}
}

func TestRoutingTableRouteExporter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	session := mock_control.NewMockPktWriter(ctrl)
	routeExporter := mock_control.NewMockRouteExporter(ctrl)

	prefixes := xtest.MustParseCIDRs(t, "192.168.100.0/24", "10.0.0.0/8")
	routingTable := dataplane.NewRoutingTable(routeExporter, []*control.RoutingChain{
		{
			Prefixes:        prefixes,
			TrafficMatchers: []control.TrafficMatcher{{ID: 1, Matcher: pktcls.CondTrue}},
		},
	})

	routeExporter.EXPECT().AddNetwork(*prefixes[0])
	routeExporter.EXPECT().AddNetwork(*prefixes[1])
	routingTable.AddRoute(1, session)

	routeExporter.EXPECT().DeleteNetwork(*prefixes[0])
	routeExporter.EXPECT().DeleteNetwork(*prefixes[1])
	routingTable.DelRoute(1)
}

type testPktWriter struct {
	ID int
}

func (_ testPktWriter) Write([]byte) {}
func (w testPktWriter) String() string {
	return fmt.Sprintf("%d", w.ID)
}
