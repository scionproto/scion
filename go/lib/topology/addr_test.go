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

var (
	pubIPv4    = RawAddrPortOverlay{RawAddrPort{"192.168.1.1", 40000}, 0}
	pubUDPIPv4 = RawAddrPortOverlay{RawAddrPort{"192.168.1.1", 40001}, 30041}
	bindIPv4   = RawAddrPort{"127.0.0.1", 40002}
	pubIPv6    = RawAddrPortOverlay{RawAddrPort{"2001:db8:a0b:12f0::1", 60000}, 0}
	pubUDPIPv6 = RawAddrPortOverlay{RawAddrPort{"2001:db8:a0b:12f0::1", 60001}, 30041}
	bindIPv6   = RawAddrPort{"::1", 60002}
	pubBad     = RawAddrPortOverlay{RawAddrPort{"BadIPAddress", 40000}, 0}
	bindBad    = RawAddrPort{"BadIPAddress", 40000}
)

func Test_TopoAddrFromRAI_Basic(t *testing.T) {
	var basic_tests = []struct {
		name    string
		overlay overlay.Type
		pub     []RawAddrPortOverlay
		bind    []RawAddrPort
		ipv4    *pubBindAddr
		ipv6    *pubBindAddr
	}{
		// IPv4
		{"IPv4 PubBind", overlay.IPv4,
			pubAddrs(pubIPv4), bindAddrs(bindIPv4),
			&pubBindAddr{newPub(&pubIPv4), newBind(&bindIPv4), newOverlay(&pubIPv4)},
			nil},
		{"IPv4 Pub", overlay.IPv4,
			pubAddrs(pubIPv4), nil,
			&pubBindAddr{newPub(&pubIPv4), nil, newOverlay(&pubIPv4)},
			nil},
		// IPv4+UDP
		{"IPv4+UDP PubBind", overlay.UDPIPv4,
			pubAddrs(pubUDPIPv4), bindAddrs(bindIPv4),
			&pubBindAddr{newPub(&pubUDPIPv4), newBind(&bindIPv4), newOverlay(&pubUDPIPv4)},
			nil},
		{"IPv4+UDP Pub", overlay.UDPIPv4,
			pubAddrs(pubUDPIPv4), nil,
			&pubBindAddr{newPub(&pubUDPIPv4), nil, newOverlay(&pubUDPIPv4)},
			nil},
		// IPv6
		{"IPv6 PubBind", overlay.IPv6,
			pubAddrs(pubIPv6), bindAddrs(bindIPv6),
			nil,
			&pubBindAddr{newPub(&pubIPv6), newBind(&bindIPv6), newOverlay(&pubIPv6)}},
		{"IPv6 Pub", overlay.IPv6,
			pubAddrs(pubIPv6), nil,
			nil,
			&pubBindAddr{newPub(&pubIPv6), nil, newOverlay(&pubIPv6)}},
		// IPv6+UDP
		{"IPv6+UDP PubBind", overlay.UDPIPv6,
			pubAddrs(pubUDPIPv6), bindAddrs(bindIPv6),
			nil,
			&pubBindAddr{newPub(&pubUDPIPv6), newBind(&bindIPv6), newOverlay(&pubUDPIPv6)}},
		{"IPv6+UDP Pub", overlay.UDPIPv6,
			pubAddrs(pubUDPIPv6), nil,
			nil,
			&pubBindAddr{newPub(&pubUDPIPv6), nil, newOverlay(&pubUDPIPv6)}},
		// IPv46
		{"IPv46 PubBind", overlay.IPv46,
			pubAddrs(pubIPv4, pubIPv6), bindAddrs(bindIPv4, bindIPv6),
			&pubBindAddr{newPub(&pubIPv4), newBind(&bindIPv4), newOverlay(&pubIPv4)},
			&pubBindAddr{newPub(&pubIPv6), newBind(&bindIPv6), newOverlay(&pubIPv6)}},
		{"IPv46 Pub", overlay.IPv46,
			pubAddrs(pubIPv4, pubIPv6), nil,
			&pubBindAddr{newPub(&pubIPv4), nil, newOverlay(&pubIPv4)},
			&pubBindAddr{newPub(&pubIPv6), nil, newOverlay(&pubIPv6)}},
		// IPv46+UDP
		{"IPv46+UDP PubBind", overlay.UDPIPv46,
			pubAddrs(pubUDPIPv4, pubUDPIPv6), bindAddrs(bindIPv4, bindIPv6),
			&pubBindAddr{newPub(&pubUDPIPv4), newBind(&bindIPv4), newOverlay(&pubUDPIPv4)},
			&pubBindAddr{newPub(&pubUDPIPv6), newBind(&bindIPv6), newOverlay(&pubUDPIPv6)}},
		{"IPv46+UDP Pub", overlay.UDPIPv46,
			pubAddrs(pubUDPIPv4, pubUDPIPv6), nil,
			&pubBindAddr{newPub(&pubUDPIPv4), nil, newOverlay(&pubUDPIPv4)},
			&pubBindAddr{newPub(&pubUDPIPv6), nil, newOverlay(&pubUDPIPv6)}},
	}
	for i, test := range basic_tests {
		desc := fmt.Sprintf("TopoAddrFromRAI_Basic %d. %s", i, test.name)
		rai := &RawAddrInfo{Public: test.pub, Bind: test.bind}
		exp := &TopoAddr{
			Overlay: test.overlay,
			IPv4:    test.ipv4,
			IPv6:    test.ipv6,
		}
		Convey(desc, t, func() {
			t, err := TopoAddrFromRAI(rai, test.overlay)
			SoMsg("Error", err, ShouldBeNil)
			SoMsg("TopoAddr", t, shouldEqTopoAddr, exp)
		})
	}
}

func Test_TopoAddrFromRAI_Errors(t *testing.T) {
	var basic_tests = []struct {
		name    string
		overlay overlay.Type
		err     []string
		pub     []RawAddrPortOverlay
		bind    []RawAddrPort
	}{
		{"Unsupported Overlay", overlay.Invalid,
			errors(ErrUnsupportedOverlay),
			nil, nil},
		{"Pub Parse Error", overlay.IPv4,
			errors(ErrInvalidPub),
			pubAddrs(pubBad), nil},
		{"Bind Parse Error", overlay.IPv4,
			errors(ErrInvalidBind),
			pubAddrs(pubIPv4), bindAddrs(bindBad)},
		{"No Addresses", overlay.IPv4,
			errors(ErrAtLeastOnePub),
			nil, nil},
		{"No Pub Address", overlay.IPv4,
			errors(ErrAtLeastOnePub),
			nil, bindAddrs(bindBad)},
		{"No UDP Overlay", overlay.IPv4,
			errors(ErrOverlayPort),
			pubAddrs(pubUDPIPv4), nil},
		// IPv4
		{"IPv4 Too Many Pub Addresses", overlay.IPv4,
			errors(ErrTooManyPubV4),
			pubAddrs(pubIPv4, pubIPv4), nil},
		{"IPv4 Too Many Bind Addresses", overlay.IPv4,
			errors(ErrTooManyBindV4),
			pubAddrs(pubIPv4), bindAddrs(bindIPv4, bindIPv4)},
		{"IPv4 Bind Without Pub Addresses", overlay.IPv4,
			errors(ErrBindWithoutPubV4),
			pubAddrs(pubIPv6), bindAddrs(bindIPv4)},
		{"IPv4 Only One Pub Address", overlay.IPv4,
			errors(ErrExactlyOnePub),
			pubAddrs(pubIPv4, pubIPv6), nil},
		{"IPv4 Bind Equals Pub Address", overlay.IPv4,
			errors(ErrBindAddrEqPubAddr),
			pubAddrs(pubIPv4), bindFromPubAddrs(pubIPv4)},
		// IPv6
		{"IPv6 Too Many Pub Addresses", overlay.IPv6,
			errors(ErrTooManyPubV6),
			pubAddrs(pubIPv6, pubIPv6), nil},
		{"IPv6 Too Many Bind Addresses", overlay.IPv6,
			errors(ErrTooManyBindV6),
			pubAddrs(pubIPv6), bindAddrs(bindIPv6, bindIPv6)},
		{"IPv6 Bind Without Pub Addresses", overlay.IPv6,
			errors(ErrBindWithoutPubV6),
			pubAddrs(pubIPv4), bindAddrs(bindIPv6)},
		{"IPv6 Only One Pub Address", overlay.IPv6,
			errors(ErrExactlyOnePub),
			pubAddrs(pubIPv4, pubIPv6), nil},
		{"IPv6 Bind Equals Pub Address", overlay.IPv6,
			errors(ErrBindAddrEqPubAddr),
			pubAddrs(pubIPv6), bindFromPubAddrs(pubIPv6)},
		// IPv46
		{"IPv46 Too Many IPv4 Pub Addresses", overlay.IPv46,
			errors(ErrTooManyPubV4),
			pubAddrs(pubIPv4, pubIPv6, pubIPv4), nil},
		{"IPv46 Too Many IPv6 Pub Addresses", overlay.IPv46,
			errors(ErrTooManyPubV6),
			pubAddrs(pubIPv4, pubIPv6, pubIPv6), nil},
	}
	for i, test := range basic_tests {
		desc := fmt.Sprintf("TopoAddrFromRAI_Errors %d. %s", i, test.name)
		rai := &RawAddrInfo{Public: test.pub, Bind: test.bind}
		Convey(desc, t, func() {
			t, err := TopoAddrFromRAI(rai, test.overlay)
			SoMsg("TopoAddr", t, ShouldBeNil)
			SoMsg("Error", err, ShouldNotBeNil)
			SoMsg("Error description", common.GetErrorMsg(err), shouldBeInStrings, test.err)
		})
	}
}

func pubAddrs(addrs ...RawAddrPortOverlay) []RawAddrPortOverlay {
	return addrs
}

func bindAddrs(addrs ...RawAddrPort) []RawAddrPort {
	return addrs
}

func bindFromPubAddrs(addrs ...RawAddrPortOverlay) []RawAddrPort {
	binds := []RawAddrPort{}
	for _, addr := range addrs {
		binds = append(binds, addr.RawAddrPort)
	}
	return binds
}

func newPub(rapo *RawAddrPortOverlay) *addr.AppAddr {
	return &addr.AppAddr{
		L3: addr.HostFromIP(net.ParseIP(rapo.Addr)),
		L4: addr.NewL4UDPInfo(uint16(rapo.L4Port)),
	}
}
func newBind(rap *RawAddrPort) *addr.AppAddr {
	return &addr.AppAddr{
		L3: addr.HostFromIP(net.ParseIP(rap.Addr)),
		L4: addr.NewL4UDPInfo(uint16(rap.L4Port)),
	}
}
func newOverlay(rapo *RawAddrPortOverlay) *overlay.OverlayAddr {
	var l4 addr.L4Info
	if rapo.OverlayPort != 0 {
		l4 = addr.NewL4UDPInfo(uint16(rapo.OverlayPort))
	}
	o, _ := overlay.NewOverlayAddr(addr.HostFromIP(net.ParseIP(rapo.Addr)), l4)
	return o
}

func shouldEqTopoAddr(actual interface{}, expected ...interface{}) string {
	//fmt.Printf("\nExpected: %+v\nActual: %+v", expected[0], actual)
	if actual.(*TopoAddr).Equal(expected[0].(*TopoAddr)) {
		return ""
	}
	return fmt.Sprintf("Expected:\n\t%+v\nActual:\n\t%+v", expected[0], actual)
}

func errors(err ...string) []string {
	return err
}

func shouldBeInStrings(actual interface{}, expected ...interface{}) string {
	for _, exp := range expected[0].([]string) {
		if actual.(string) == exp {
			return ""
		}
	}
	return fmt.Sprintf("Expected a member of: %+q\nActual: %+q", expected, actual)
}
