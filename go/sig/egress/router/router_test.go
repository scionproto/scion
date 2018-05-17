// Copyright 2018 ETH Zurich
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

package router

import (
	"fmt"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

var (
	iaA   = addr.IA{I: 1, A: 0xff0000000000}
	iaB   = addr.IA{I: 1, A: 0xff0000000001}
	iaMap = map[addr.IA][]string{
		iaA: {"192.0.2.0/30", "192.0.2.8/30", "2001:db8::/48", "2001:db8:2::/48"},
		iaB: {"192.0.2.4/30", "2001:db8:1::/48"},
	}
)

func parseNet(t *testing.T, s string) *net.IPNet {
	t.Helper()

	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return ipnet
}

func defNetworks(t *testing.T) *Networks {
	t.Helper()

	nets := &Networks{}
	for ia, v := range iaMap {
		for _, n := range v {
			if err := nets.Add(parseNet(t, n), ia, &ringbuf.Ring{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return nets
}

func Test_Networks_Add(t *testing.T) {
	var testCases = []struct {
		nets  []string
		count int
		ok    bool
	}{
		{[]string{"192.0.2.0/24"}, 1, true},
		{[]string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}, 3, true},
		{[]string{"2001:db8::/32"}, 1, true},
		{[]string{"2001:db8::/48", "2001:db8:1::/48", "2001:db8:2::/48"}, 3, true},
		{[]string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
			"2001:db8::/48", "2001:db8:1::/48", "2001:db8:2::/48"}, 6, true},
		// Test canonicalisation
		{[]string{"192.0.2.0/24", "192.0.2.1/24"}, 1, false},
		{[]string{"2001:db8::/48", "2001:db8::1/48"}, 1, false},
		// Test adding supernet
		{[]string{"192.0.2.0/25", "192.0.2.0/24"}, 1, false},
		{[]string{"2001:db8::/49", "2001:db8::/48"}, 1, false},
		// Test adding subnet
		{[]string{"192.0.2.0/24", "192.0.2.0/25"}, 1, false},
		{[]string{"2001:db8::/48", "2001:db8::/49"}, 1, false},
	}
	Convey("Networks.Add()", t, func() {
		nets := &Networks{}
		for _, tc := range testCases {
			Convey(fmt.Sprintf("%q", tc.nets), func() {
				ok := true
				for i := range tc.nets {
					err := nets.Add(
						parseNet(t, tc.nets[i]),
						addr.IA{I: addr.MaxISD, A: addr.MaxAS},
						&ringbuf.Ring{},
					)
					if err != nil {
						ok = false
					}
				}
				if tc.ok {
					SoMsg("No errors should happen", ok, ShouldBeTrue)
				} else {
					SoMsg("Errors should be thrown", ok, ShouldBeFalse)
				}
				SoMsg("There should be the correct number of networks",
					len(nets.nets), ShouldEqual, tc.count)
			})
		}
	})
}

func Test_Networks_Delete(t *testing.T) {
	var testCases = []struct {
		net string
		ok  bool
	}{
		{"192.0.2.0/24", false},
		{"192.0.2.0/31", false},
		{"192.0.2.0/29", false},
		{"192.0.2.0/30", true},
		{"192.0.2.1/30", true},
		{"192.0.2.4/30", true},
		{"192.0.2.12/30", false},
		{"2001:db8::/32", false},
		{"2001:db8::/49", false},
		{"2001:db8::/47", false},
		{"2001:db8::/48", true},
		{"2001:db8::1/48", true},
		{"2001:db8:1::/48", true},
		{"2001:db8:3::/48", false},
	}
	Convey("Networks.Delete()", t, func() {
		nets := defNetworks(t)
		numNets := len(nets.nets)
		for _, tc := range testCases {
			Convey(tc.net, func() {
				delNet := parseNet(t, tc.net)
				cdelNet := newCanonNet(delNet)
				err := nets.Delete(delNet)
				if tc.ok {
					SoMsg("Delete should succeed", err, ShouldBeNil)
					SoMsg("Number of nets should have reduced",
						len(nets.nets), ShouldEqual, numNets-1)
					for _, n := range nets.nets {
						if cdelNet.Equal(n.net) {
							SoMsg("Network should not be present anymore", true, ShouldBeFalse)
						}
					}
				} else {
					SoMsg("Delete should fail", err, ShouldNotBeNil)
				}
			})
		}
	})
}

func Test_Networks_Lookup(t *testing.T) {
	var testCases = []struct {
		ip string
		ia addr.IA
	}{
		{"192.0.2.0", iaA},
		{"192.0.2.1", iaA},
		{"192.0.2.2", iaA},
		{"192.0.2.3", iaA},
		{"192.0.2.4", iaB},
		{"192.0.2.7", iaB},
		{"192.0.2.8", iaA},
		{"192.0.2.11", iaA},
		{"192.0.2.12", addr.IA{}},
		{"2001:db8::0", iaA},
		{"2001:db8::1", iaA},
		{"2001:db8::ffff:ffff:ffff:ffff:ffff", iaA},
		{"2001:db8:1::", iaB},
		{"2001:db8:1:ffff:ffff:ffff:ffff:ffff", iaB},
		{"2001:db8:3::", addr.IA{}},
	}
	Convey("Networks.Lookup()", t, func() {
		nets := defNetworks(t)
		for _, tc := range testCases {
			Convey(tc.ip, func() {
				ia, ring := nets.Lookup(net.ParseIP(tc.ip))
				if tc.ia.IsZero() {
					SoMsg("Lookup should fail", ring, ShouldBeNil)
				} else {
					SoMsg("Lookup should succeed", ring, ShouldNotBeNil)
					SoMsg("IA should match", ia, ShouldResemble, tc.ia)
				}
			})
		}
	})
}

func Test_ipNet_Equal(t *testing.T) {
	var testCases = []struct {
		netA string
		netB string
		ok   bool
	}{
		{"192.0.2.0/32", "192.0.2.1/32", false},
		{"192.0.2.0/24", "192.0.2.255/24", true},
		{"192.0.2.3/24", "192.0.2.6/24", true},
		{"2001:db8::/128", "2001:db8::/128", true},
		{"2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/32", true},
		{"2001:db8::abcd/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/32", true},
	}
	Convey("ipNet.Equal()", t, func() {
		for _, tc := range testCases {
			Convey(fmt.Sprintf("%s <> %s", tc.netA, tc.netB), func() {
				netA := newCanonNet(parseNet(t, tc.netA))
				netB := newCanonNet(parseNet(t, tc.netB))
				SoMsg("netA == netB", netA.Equal(netB), ShouldEqual, tc.ok)
				SoMsg("netB == netA", netB.Equal(netA), ShouldEqual, tc.ok)
			})
		}
	})
}
