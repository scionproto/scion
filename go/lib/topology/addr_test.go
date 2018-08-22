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
	"fmt"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
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

var hV4Pub = addr.HostIPv4(net.ParseIP(rawV4Pub))
var hV4Bind = addr.HostIPv4(net.ParseIP(rawV4Bind))
var hV6Pub = addr.HostIPv6(net.ParseIP(rawV6Pub))
var hV6Bind = addr.HostIPv6(net.ParseIP(rawV6Bind))

var oV4, _ = overlay.NewOverlayAddr(hV4Pub, nil)
var oV6, _ = overlay.NewOverlayAddr(hV6Pub, nil)
var oV4UDP, _ = overlay.NewOverlayAddr(hV4Pub, addr.NewL4UDPInfo(30041))
var oV6UDP, _ = overlay.NewOverlayAddr(hV6Pub, addr.NewL4UDPInfo(30041))

// TopoAddr's for ipv4
var taV4Both = &pubBindAddr{
	pub:     &addr.AppAddr{L3: hV4Pub, L4: addr.NewL4UDPInfo(40000)},
	bind:    &addr.AppAddr{L3: hV4Bind, L4: addr.NewL4UDPInfo(40002)},
	overlay: oV4,
}
var taV4Pub = &pubBindAddr{
	pub:     &addr.AppAddr{L3: hV4Pub, L4: addr.NewL4UDPInfo(40000)},
	bind:    nil,
	overlay: oV4,
}
var taV4UDPBoth = &pubBindAddr{
	pub:     &addr.AppAddr{L3: hV4Pub, L4: addr.NewL4UDPInfo(40001)},
	bind:    &addr.AppAddr{L3: hV4Bind, L4: addr.NewL4UDPInfo(40002)},
	overlay: oV4UDP,
}
var taV4UDPPub = &pubBindAddr{
	pub:     &addr.AppAddr{L3: hV4Pub, L4: addr.NewL4UDPInfo(40001)},
	bind:    nil,
	overlay: oV4UDP,
}

// TopoAddr's for ipv6
var taV6Both = &pubBindAddr{
	pub:     &addr.AppAddr{L3: hV6Pub, L4: addr.NewL4UDPInfo(60000)},
	bind:    &addr.AppAddr{L3: hV6Bind, L4: addr.NewL4UDPInfo(60002)},
	overlay: oV6,
}
var taV6Pub = &pubBindAddr{
	pub:     &addr.AppAddr{L3: hV6Pub, L4: addr.NewL4UDPInfo(60000)},
	bind:    nil,
	overlay: oV6,
}
var taV6UDPBoth = &pubBindAddr{
	pub:     &addr.AppAddr{L3: hV6Pub, L4: addr.NewL4UDPInfo(60001)},
	bind:    &addr.AppAddr{L3: hV6Bind, L4: addr.NewL4UDPInfo(60002)},
	overlay: oV6UDP,
}
var taV6UDPPub = &pubBindAddr{
	pub:     &addr.AppAddr{L3: hV6Pub, L4: addr.NewL4UDPInfo(60001)},
	bind:    nil,
	overlay: oV6UDP,
}

// TopoAddr's for ipv4+6
var taV46Both4 = taV4Both
var taV46Both6 = taV6Both
var taV46Pub4 = taV4Pub
var taV46Pub6 = taV6Pub
var taV46UDPBoth4 = taV4UDPBoth
var taV46UDPBoth6 = taV6UDPBoth
var taV46UDPPub4 = taV4UDPPub
var taV46UDPPub6 = taV6UDPPub

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
	if actual.(*pubBindAddr).equal(expected[0].(*pubBindAddr)) {
		return ""
	}
	return fmt.Sprintf("Expected: %+v\nActual: %+v", expected[0], actual)
}

func shouldBeInStrings(actual interface{}, expected ...interface{}) string {
	for _, exp := range expected[0].([]string) {
		if actual.(string) == exp {
			return ""
		}
	}
	return fmt.Sprintf("Expected a member of: %+q\nActual: %+q", expected, actual)
}

func Test_ToTopoAddr_Basic(t *testing.T) {
	var basic_tests = []struct {
		name  string
		ot    overlay.Type
		in    *RawAddrInfo
		expV4 *pubBindAddr
		expV6 *pubBindAddr
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
	name    string
	in      *RawAddrInfo
	errDesc []string
}

func mkErrorTests(ot overlay.Type) []errorTest {
	if ot.IsIPv4() != ot.IsIPv6() {
		return mkErrorTestsSingle(ot)
	}
	return mkErrorTestsDual(ot)
}

func mkErrorTest(name string, pubAddrs []testRAIOver,
	bindAddrs []RawAddrPort, desc ...string) errorTest {
	return errorTest{name, mkRAI(pubAddrs, bindAddrs), desc}
}

func mkErrorTestsSingle(ot overlay.Type) []errorTest {
	over_info := map[overlay.Type]struct {
		pubs  []testRAIOver
		binds []RawAddrPort
	}{
		overlay.IPv4:    {[]testRAIOver{v4Pub}, []RawAddrPort{v4Bind}},
		overlay.UDPIPv4: {[]testRAIOver{v4PubUDP}, []RawAddrPort{v4Bind}},
		overlay.IPv6:    {[]testRAIOver{v6Pub}, []RawAddrPort{v6Bind}},
		overlay.UDPIPv6: {[]testRAIOver{v6PubUDP}, []RawAddrPort{v6Bind}},
	}
	info := over_info[ot]
	tests := []errorTest{
		mkErrorTest("pub parse error",
			[]testRAIOver{{"bad pub ip", 40000, 0}}, nil, ErrInvalidPub),
		mkErrorTest("bind parse error", info.pubs,
			[]RawAddrPort{{"bad bind ip", 40002}}, ErrInvalidBind),
		mkErrorTest("no addrs", nil, nil, ErrExactlyOnePub, ErrAtLeastOnePub),
		mkErrorTest("no pub addr", nil, info.binds, ErrBindWithoutPubV4, ErrBindWithoutPubV6,
			ErrAtLeastOnePub),
		mkErrorTest("too many pub addrs", append(info.pubs, info.pubs[0]), nil,
			ErrTooManyPubV4, ErrTooManyPubV6),
		mkErrorTest("too many bind addrs", info.pubs, append(info.binds, info.binds[0]),
			ErrTooManyBindV4, ErrTooManyBindV6),
	}
	if !ot.IsUDP() {
		tests = append(tests, mkErrorTestNotUDP(info.pubs))
	}
	return tests
}

func mkErrorTestsDual(ot overlay.Type) []errorTest {
	over_info := map[overlay.Type]struct {
		pubs  []testRAIOver
		binds []RawAddrPort
	}{
		overlay.IPv46:   {[]testRAIOver{v4Pub, v6Pub}, []RawAddrPort{v4Bind, v6Bind}},
		overlay.UDPIPv4: {[]testRAIOver{v4PubUDP, v6PubUDP}, []RawAddrPort{v4Bind, v6Bind}},
	}
	info := over_info[ot]
	tests := []errorTest{
		mkErrorTest("no addrs", nil, nil, ErrAtLeastOnePub),
		mkErrorTest("no pub addrs", nil, info.binds, ErrBindWithoutPubV4, ErrBindWithoutPubV6,
			ErrAtLeastOnePub),
		mkErrorTest("too many pub v4", append(info.pubs, info.pubs[0]), nil, ErrTooManyPubV4),
		mkErrorTest("too many pub v6", append(info.pubs, info.pubs[1]), nil, ErrTooManyPubV6),
		mkErrorTest("too many bind v4", info.pubs, append(info.binds, info.binds[0]),
			ErrTooManyBindV4),
		mkErrorTest("too many bind v6", info.pubs, append(info.binds, info.binds[1]),
			ErrTooManyBindV6),
		mkErrorTest("bind v4 without pub", info.pubs[1:], info.binds, ErrBindWithoutPubV4),
		mkErrorTest("bind v6 without pub", info.pubs[:1], info.binds, ErrBindWithoutPubV6),
	}
	if !ot.IsUDP() {
		tests = append(tests, mkErrorTestNotUDP(info.pubs))
	}
	return tests
}

func mkErrorTestNotUDP(pubAddrs []testRAIOver) errorTest {
	// Copy the public addrs
	badOverlay := append([]testRAIOver(nil), pubAddrs...)
	// Set the overlay port of the first public addr
	badOverlay[0].overPort = 1
	return mkErrorTest("overlay port set", badOverlay, nil, ErrOverlayPort)
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
				SoMsg("Error description", common.GetErrorMsg(err), shouldBeInStrings, test.errDesc)
			})
		}
	}
}
