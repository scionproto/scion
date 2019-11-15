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

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/topology/overlay"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	pubIPv4    = &RawAddrPortOverlay{RawAddrPort{"192.168.1.1", 40000}, 0}
	pubUDPIPv4 = &RawAddrPortOverlay{RawAddrPort{"192.168.1.1", 40001}, 30041}
	bindIPv4   = &RawAddrPort{"127.0.0.1", 40002}
	pubIPv6    = &RawAddrPortOverlay{RawAddrPort{"2001:db8:a0b:12f0::1", 60000}, 0}
	pubUDPIPv6 = &RawAddrPortOverlay{RawAddrPort{"2001:db8:a0b:12f0::1", 60001}, 30041}
	bindIPv6   = &RawAddrPort{"::1", 60002}
	pubBad     = &RawAddrPortOverlay{RawAddrPort{"BadIPAddress", 40000}, 0}
	bindBad    = &RawAddrPort{"BadIPAddress", 40000}
)

func Test_topoAddrFromRaw(t *testing.T) {
	var basic_tests = []struct {
		name    string
		overlay overlay.Type
		err     error
		ram     RawAddrMap
		ipv4    *pubBindAddr
		ipv6    *pubBindAddr
	}{
		// Common Errors
		{"Unsupported Overlay", overlay.Invalid,
			ErrUnsupportedOverlay,
			nil, nil, nil},
		{"Unsupported Address Type", overlay.IPv4,
			ErrUnsupportedAddrType,
			newRAMError("MPLS", pubIPv4, nil), nil, nil},
		{"No Addresses", overlay.IPv4,
			ErrAtLeastOnePub,
			make(RawAddrMap), nil, nil},
		// IPv4 Errors
		{"IPv4 Overlay Mismatch", overlay.IPv6,
			ErrMismatchOverlayAddr,
			newRAM(pubIPv4, nil, nil, nil), nil, nil},
		{"IPv4 Invalid Pub Address", overlay.IPv4,
			ErrMismatchPubAddrType,
			newRAM(pubIPv6, nil, nil, nil), nil, nil},
		{"IPv4 Invalid Bind Address", overlay.IPv4,
			ErrMismatchBindAddrType,
			newRAM(pubIPv4, nil, bindIPv6, nil), nil, nil},
		{"IPv4 Same Pub/Bind Address", overlay.IPv4,
			ErrBindAddrEqPubAddr,
			newRAM(pubIPv4, nil, &pubIPv4.RawAddrPort, nil), nil, nil},
		// IPv6 Errors
		{"IPv6 Overlay Mismatch", overlay.IPv4,
			ErrMismatchOverlayAddr,
			newRAM(nil, pubIPv6, nil, nil), nil, nil},
		{"IPv6 Invalid Pub Address", overlay.IPv6,
			ErrMismatchPubAddrType,
			newRAM(nil, pubIPv4, nil, nil), nil, nil},
		{"IPv6 Invalid Bind Address", overlay.IPv6,
			ErrMismatchBindAddrType,
			newRAM(nil, pubIPv6, nil, bindIPv4), nil, nil},
		{"IPv6 Same Pub/Bind Address", overlay.IPv6,
			ErrBindAddrEqPubAddr,
			newRAM(nil, pubIPv6, nil, &pubIPv6.RawAddrPort), nil, nil},
		// IPv46
		{"IPv46 PubBind", overlay.IPv46, nil,
			newRAM(pubIPv4, pubIPv6, bindIPv4, bindIPv6),
			&pubBindAddr{newPub(pubIPv4), newBind(bindIPv4), newOverlay(pubIPv4)},
			&pubBindAddr{newPub(pubIPv6), newBind(bindIPv6), newOverlay(pubIPv6)}},
		// IPv46+UDP
		{"IPv46+UDP PubBind", overlay.UDPIPv46, nil,
			newRAM(pubUDPIPv4, pubUDPIPv6, bindIPv4, bindIPv6),
			&pubBindAddr{newPub(pubUDPIPv4), newBind(bindIPv4), newOverlay(pubUDPIPv4)},
			&pubBindAddr{newPub(pubUDPIPv6), newBind(bindIPv6), newOverlay(pubUDPIPv6)}},
	}
	for i, test := range basic_tests {
		desc := fmt.Sprintf("topoAddrFromRaw_%d. %s", i, test.name)
		exp := &TopoAddr{
			IPv4:    test.ipv4,
			IPv6:    test.ipv6,
			Overlay: test.overlay,
		}
		t.Run(desc, func(t *testing.T) {
			ta, err := topoAddrFromRAM(test.ram, test.overlay)
			xtest.AssertErrorsIs(t, err, test.err)
			if test.err == nil {
				assert.Equal(t, exp, ta)
			}
		})
	}
}

func Test_pubBindAddr(t *testing.T) {
	var basic_tests = []struct {
		name       string
		udpOverlay bool
		pub        *RawAddrPortOverlay
		overlay    *RawAddrPortOverlay
		bind       *RawAddrPort
		err        error
	}{
		// Errors
		{"Invaild Public IP Address", false, pubBad, nil, nil, ErrInvalidPub},
		{"Invaild Bind IP Address", false, pubIPv4, nil, bindBad, ErrInvalidBind},
		// IPv4 Overlay
		{"IPv4 Pub", false, pubIPv4, nil, nil, nil},
		{"IPv4 PubBind", false, pubIPv4, nil, bindIPv4, nil},
		// IPv4+UDP Overlay
		{"IPv4+UDP Pub", true, pubUDPIPv4, nil, nil, nil},
		{"IPv4+UDP Pub Default Port", true, pubIPv4, pubUDPIPv4, nil, nil},
		{"IPv4+UDP PubBind", true, pubUDPIPv4, nil, bindIPv4, nil},
		// IPv6 Overlay
		{"IPv6 Pub", false, pubIPv6, nil, nil, nil},
		{"IPv6 PubBind", false, pubIPv6, nil, bindIPv6, nil},
		// IPv6+UDP Overlay
		{"IPv6+UDP Pub", true, pubUDPIPv6, nil, nil, nil},
		{"IPv6+UDP Pub Default Port", true, pubIPv6, pubUDPIPv6, nil, nil},
		{"IPv6+UDP PubBind", true, pubUDPIPv6, nil, bindIPv6, nil},
	}
	for i, test := range basic_tests {
		desc := fmt.Sprintf("pubBindAddr_%d. %s", i, test.name)
		rpbo := &RawPubBindOverlay{*test.pub, test.bind}
		overlay := test.pub
		if test.overlay != nil {
			overlay = test.overlay
		}
		exp := &pubBindAddr{newPub(test.pub), newBind(test.bind), newOverlay(overlay)}
		t.Run(desc, func(t *testing.T) {
			pbo := &pubBindAddr{}
			err := pbo.fromRaw(rpbo, test.udpOverlay)
			xtest.AssertErrorsIs(t, err, test.err)
			if test.err == nil {
				assert.Equal(t, exp, pbo)
			}
		})
	}
}

func newRAM(pub4, pub6 *RawAddrPortOverlay, bind4, bind6 *RawAddrPort) RawAddrMap {
	rai := make(RawAddrMap)
	if pub4 != nil {
		rai["IPv4"] = &RawPubBindOverlay{Public: *pub4, Bind: bind4}
	}
	if pub6 != nil {
		rai["IPv6"] = &RawPubBindOverlay{Public: *pub6, Bind: bind6}
	}
	return rai
}

func newRAMError(t string, pub *RawAddrPortOverlay, bind *RawAddrPort) RawAddrMap {
	ram := make(RawAddrMap)
	ram[t] = &RawPubBindOverlay{Public: *pub, Bind: bind}
	return ram
}

func shouldEqTopoAddr(actual interface{}, expected ...interface{}) string {
	//fmt.Printf("\nExpected: %+v\nActual: %+v", expected[0], actual)
	if actual.(*TopoAddr).Equal(expected[0].(*TopoAddr)) {
		return ""
	}
	return fmt.Sprintf("Expected:\n\t%+v\nActual:\n\t%+v", expected[0], actual)
}

func newPub(rapo *RawAddrPortOverlay) *addr.AppAddr {
	if rapo == nil {
		return nil
	}
	return &addr.AppAddr{
		L3: addr.HostFromIPStr(rapo.Addr),
		L4: uint16(rapo.L4Port),
	}
}

func newBind(rap *RawAddrPort) *addr.AppAddr {
	if rap == nil {
		return nil
	}
	return &addr.AppAddr{
		L3: addr.HostFromIPStr(rap.Addr),
		L4: uint16(rap.L4Port),
	}
}

func newOverlay(rapo *RawAddrPortOverlay) *overlay.OverlayAddr {
	if rapo == nil {
		return nil
	}
	ip := net.ParseIP(rapo.Addr)
	if ip.To4() != nil {
		ip = ip.To4()
	}
	return overlay.NewOverlayAddr(ip, uint16(rapo.OverlayPort))
}

func shouldEqPubBindAddr(actual interface{}, expected ...interface{}) string {
	if actual.(*pubBindAddr).Equal(expected[0].(*pubBindAddr)) {
		return ""
	}
	return fmt.Sprintf("Expected:\n\t%+v\nActual:\n\t%+v", expected[0], actual)
}
