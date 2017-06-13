// Copyright 2017 ETH Zurich
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

	// External
	. "github.com/smartystreets/goconvey/convey"

	// Local
	//"github.com/netsec-ethz/scion/go/lib/addr"
	//"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
)

type testRAIOver struct {
	ip       string
	l4port   int
	overPort int
}

var rawV4Pub = "192.168.1.1"
var rawV4Bind = "127.0.0.1"
var rawV6Pub = "2001:db8:a0b:12f0::1"
var rawV6Bind = "::1"

// Basic addresses to combine for tests.
var v4Pub = testRAIOver{rawV4Pub, 40000, 0}
var v4PubUDP = testRAIOver{rawV4Pub, 40001, 30041}
var v4Bind = RawAddrPort{rawV4Bind, 40002}
var v6Pub = testRAIOver{rawV6Pub, 60000, 0}
var v6PubUDP = testRAIOver{rawV6Pub, 60001, 30041}
var v6Bind = RawAddrPort{rawV6Bind, 60002}

// RawAddrInfo's for ipv4
var raiV4Both = mkRAI([]testRAIOver{v4Pub}, []RawAddrPort{v4Bind})
var raiV4Pub = mkRAI([]testRAIOver{v4Pub}, nil)
var raiV4UDPBoth = mkRAI([]testRAIOver{v4PubUDP}, []RawAddrPort{v4Bind})
var raiV4UDPPub = mkRAI([]testRAIOver{v4PubUDP}, nil)
var raiV4Bind = mkRAI(nil, []RawAddrPort{v4Bind})

// RawAddrInfo's for ipv6
var raiV6Both = mkRAI([]testRAIOver{v6Pub}, []RawAddrPort{v6Bind})
var raiV6Pub = mkRAI([]testRAIOver{v6Pub}, nil)
var raiV6UDPBoth = mkRAI([]testRAIOver{v6PubUDP}, []RawAddrPort{v6Bind})
var raiV6UDPPub = mkRAI([]testRAIOver{v6PubUDP}, nil)
var raiV6Bind = mkRAI(nil, []RawAddrPort{v6Bind})

// RawAddrInfo's for ipv4+6
var raiV46Both = mkRAI([]testRAIOver{v4Pub, v6Pub}, []RawAddrPort{v4Bind, v6Bind})
var raiV46Pub = mkRAI([]testRAIOver{v6Pub, v4Pub}, nil)
var raiV46UDPBoth = mkRAI([]testRAIOver{v4PubUDP, v6PubUDP}, []RawAddrPort{v6Bind, v4Bind})
var raiV46UDPPub = mkRAI([]testRAIOver{v4PubUDP, v6PubUDP}, nil)
var raiV46Bind = mkRAI(nil, []RawAddrPort{v4Bind, v6Bind})

// TopoAddr's for ipv4
var taV4Both = &topoAddrInt{net.ParseIP(rawV4Pub), 40000, net.ParseIP(rawV4Bind), 40002, 0}
var taV4Pub = &topoAddrInt{net.ParseIP(rawV4Pub), 40000, nil, 0, 0}
var taV4UDPBoth = &topoAddrInt{net.ParseIP(rawV4Pub), 40001, net.ParseIP(rawV4Bind), 40002, 30041}
var taV4UDPPub = &topoAddrInt{net.ParseIP(rawV4Pub), 40001, nil, 0, 30041}

// TopoAddr's for ipv6
var taV6Both = &topoAddrInt{net.ParseIP(rawV6Pub), 60000, net.ParseIP(rawV6Bind), 60002, 0}
var taV6Pub = &topoAddrInt{net.ParseIP(rawV6Pub), 60000, nil, 0, 0}
var taV6UDPBoth = &topoAddrInt{net.ParseIP(rawV6Pub), 60001, net.ParseIP(rawV6Bind), 60002, 30041}
var taV6UDPPub = &topoAddrInt{net.ParseIP(rawV6Pub), 60001, nil, 0, 30041}

// TopoAddr's for ipv4+6
var taV46Both4 = &topoAddrInt{net.ParseIP(rawV4Pub), 40000, net.ParseIP(rawV4Bind), 40002, 0}
var taV46Both6 = &topoAddrInt{net.ParseIP(rawV6Pub), 60000, net.ParseIP(rawV6Bind), 60002, 0}
var taV46Pub4 = &topoAddrInt{net.ParseIP(rawV4Pub), 40000, nil, 0, 0}
var taV46Pub6 = &topoAddrInt{net.ParseIP(rawV6Pub), 60000, nil, 0, 0}
var taV46UDPBoth4 = &topoAddrInt{net.ParseIP(rawV4Pub), 40001, net.ParseIP(rawV4Bind), 40002, 30041}
var taV46UDPBoth6 = &topoAddrInt{net.ParseIP(rawV6Pub), 60001, net.ParseIP(rawV6Bind), 60002, 30041}
var taV46UDPPub4 = &topoAddrInt{net.ParseIP(rawV4Pub), 40001, nil, 0, 30041}
var taV46UDPPub6 = &topoAddrInt{net.ParseIP(rawV6Pub), 60001, nil, 0, 30041}

func mkRAI(pub []testRAIOver, bind []RawAddrPort) *RawAddrInfo {
	rai := &RawAddrInfo{}
	for _, entry := range pub {
		rai.Public = append(rai.Public, RawAddrPortOverlay{
			RawAddrPort: RawAddrPort{Addr: entry.ip, L4Port: entry.l4port},
			OverlayPort: entry.overPort})
	}
	rai.Bind = bind
	return rai
}

func shouldEqTopoAddr(actual interface{}, expected ...interface{}) string {
	if actual.(*topoAddrInt).equal(expected[0].(*topoAddrInt)) {
		return ""
	}
	return fmt.Sprintf("Expected: %+v\nActual: %+v", expected[0], actual)
}

func Test_ToTopoAddr_Basic(t *testing.T) {
	var basic_tests = []struct {
		name  string
		ot    overlay.Type
		in    *RawAddrInfo
		expV4 *topoAddrInt
		expV6 *topoAddrInt
	}{
		{"IPv4 Both", overlay.IPv4, raiV4Both, taV4Both, nil},
		{"IPv4 Pub", overlay.IPv4, raiV4Pub, taV4Pub, nil},
		{"IPv4+UDP Both", overlay.UDPIPv4, raiV4UDPBoth, taV4UDPBoth, nil},
		{"IPv4+UDP Pub", overlay.UDPIPv4, raiV4UDPPub, taV4UDPPub, nil},
		{"IPv6 Both", overlay.IPv6, raiV6Both, nil, taV6Both},
		{"IPv6 Pub", overlay.IPv6, raiV6Pub, nil, taV6Pub},
		{"IPv6+UDP Both", overlay.UDPIPv6, raiV6UDPBoth, nil, taV6UDPBoth},
		{"IPv6+UDP Pub", overlay.UDPIPv6, raiV6UDPPub, nil, taV6UDPPub},
		{"IPv4+6 Both", overlay.IPv46, raiV46Both, taV46Both4, taV46Both6},
		{"IPv4+6 Pub", overlay.IPv46, raiV46Pub, taV46Pub4, taV46Pub6},
		{"IPv4+6+UDP Both", overlay.UDPIPv46, raiV46UDPBoth, taV46UDPBoth4, taV46UDPBoth6},
		{"IPv4+6+UDP Pub", overlay.UDPIPv46, raiV46UDPPub, taV46UDPPub4, taV46UDPPub6},
	}
	for i, test := range basic_tests {
		desc := fmt.Sprintf("ToTopoAddr_Basic %d. %s", i, test.name)
		Convey(desc, t, func() {
			t, err := test.in.ToTopoAddr(test.ot)
			SoMsg("Error", err, ShouldBeNil)
			SoMsg("IPv4", t.IPv4, shouldEqTopoAddr, test.expV4)
			SoMsg("IPv6", t.IPv6, shouldEqTopoAddr, test.expV6)
			SoMsg("Overlay", t.Overlay, ShouldEqual, test.ot)
		})
	}
}

type errorTest struct {
	name       string
	in         *RawAddrInfo
	errSnippet string
}

func mkErrorTests(ot overlay.Type) []errorTest {
	if ot.IsIPv4() != ot.IsIPv6() {
		return mkErrorTestsSingle(ot)
	}
	return mkErrorTestsDual(ot)
}

func mkErrorTestsSingle(ot overlay.Type) []errorTest {
	var pubAddr = v4Pub
	var bindAddr = v4Bind
	switch ot {
	case overlay.UDPIPv4:
		pubAddr = v4PubUDP
	case overlay.IPv6:
		pubAddr = v6Pub
		bindAddr = v6Bind
	case overlay.UDPIPv6:
		pubAddr = v6PubUDP
		bindAddr = v6Bind
	}
	badPub := pubAddr
	badPub.ip = "bad pub ip"
	badBind := bindAddr
	badBind.Addr = "bad bind ip"
	tests := []errorTest{
		{"pub parse error", mkRAI([]testRAIOver{badPub}, nil), "Invalid public"},
		{"bind parse error", mkRAI([]testRAIOver{pubAddr}, []RawAddrPort{badBind}), "Invalid bind"},
		{"no pub addr", mkRAI(nil, nil), "must have exactly one public address"},
		{"too many pub addrs", mkRAI([]testRAIOver{pubAddr, pubAddr}, nil),
			"must have exactly one public address"},
		{"too many bind addrs", mkRAI([]testRAIOver{pubAddr}, []RawAddrPort{bindAddr, bindAddr}),
			"must have at most one bind address"},
	}
	if !ot.IsUDP() {
		tests = append(tests, mkErrorTestNotUDP([]testRAIOver{pubAddr}))
	}
	return tests
}

func mkErrorTestsDual(ot overlay.Type) []errorTest {
	var pubAddrs = []testRAIOver{v4Pub, v6Pub}
	var bindAddrs = []RawAddrPort{v4Bind, v6Bind}
	if ot.IsUDP() {
		pubAddrs = []testRAIOver{v4PubUDP, v6PubUDP}
	}
	badPubs := append([]testRAIOver(nil), pubAddrs...)
	badPubs[1].ip = "bad pub v6 ip"
	badBinds := append([]RawAddrPort(nil), bindAddrs...)
	badBinds[0].Addr = "bad bind v4 ip"
	tests := []errorTest{
		{"pub parse error", mkRAI(badPubs, nil), "Invalid public"},
		{"bind parse error", mkRAI(pubAddrs, badBinds), "Invalid bind"},
		{"no pub addr", mkRAI(nil, nil), "must have at least one public address"},
		{"multiple pub v4", mkRAI(append(pubAddrs, pubAddrs[0]), nil),
			"have more than one public IPv4 address"},
		{"multiple pub v6", mkRAI(append(pubAddrs, pubAddrs[1]), nil),
			"have more than one public IPv6 address"},
		{"multiple bind v4", mkRAI(pubAddrs, append(bindAddrs, bindAddrs[0])),
			"have more than one IPv4 bind address"},
		{"multiple bind v6", mkRAI(pubAddrs, append(bindAddrs, bindAddrs[1])),
			"have more than one IPv6 bind address"},
	}
	if !ot.IsUDP() {
		tests = append(tests, mkErrorTestNotUDP(pubAddrs))
	}
	return tests
}

func mkErrorTestNotUDP(pubAddrs []testRAIOver) errorTest {
	badOverlay := append([]testRAIOver(nil), pubAddrs...)
	badOverlay[0].overPort = 1
	return errorTest{
		"overlay port set", mkRAI(badOverlay, nil), "Overlay port set for non-UDP overlay",
	}
}

func Test_ToTopoAddr_Errors(t *testing.T) {
	for _, ot := range []overlay.Type{
		overlay.IPv4, overlay.UDPIPv4, overlay.IPv6, overlay.UDPIPv6, overlay.IPv46,
	} {
		for i, test := range mkErrorTests(ot) {
			desc := fmt.Sprintf("ToTopoAddr_Errors %s %d. %s", ot, i, test.name)
			Convey(desc, t, func() {
				_, err := test.in.ToTopoAddr(ot)
				SoMsg("Error returned", err, ShouldNotBeNil)
				SoMsg("Error description", err.Desc, ShouldContainSubstring, test.errSnippet)
			})
		}
	}
}
