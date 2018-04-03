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

package pktcls

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/smartystreets/goconvey/convey"
)

func TestBasicCond(t *testing.T) {
	testCases := []struct {
		Name    string
		Cond    Cond
		ExpEval bool
	}{
		{
			Name:    "Any()",
			Cond:    NewCondAnyOf(),
			ExpEval: true,
		},
		{
			Name:    "Any(True)",
			Cond:    NewCondAnyOf(CondTrue),
			ExpEval: true,
		},
		{
			Name:    "Any(False)",
			Cond:    NewCondAnyOf(CondFalse),
			ExpEval: false,
		},
		{
			Name:    "Any(False, True, False)",
			Cond:    NewCondAnyOf(CondFalse, CondTrue, CondFalse),
			ExpEval: true,
		},
		{
			Name:    "All()",
			Cond:    NewCondAllOf(),
			ExpEval: true,
		},
		{
			Name:    "All(True)",
			Cond:    NewCondAllOf(CondTrue),
			ExpEval: true,
		},
		{
			Name:    "All(False)",
			Cond:    NewCondAllOf(CondFalse),
			ExpEval: false,
		},
		{
			Name:    "All(False, True, False)",
			Cond:    NewCondAllOf(CondFalse, CondTrue, CondFalse),
			ExpEval: false,
		},
		{
			Name:    "All(Any(), All(), False)",
			Cond:    NewCondAllOf(NewCondAnyOf(), NewCondAllOf(), CondFalse),
			ExpEval: false,
		},
		{
			Name:    "All(Any(), All(), Not(Not(True)))",
			Cond:    NewCondAllOf(NewCondAnyOf(), NewCondAllOf(), NewCondNot(NewCondNot(CondTrue))),
			ExpEval: true,
		},
	}

	Convey("TestCond", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				SoMsg("eval", tc.Cond.Eval(nil), ShouldEqual, tc.ExpEval)
			})
		}
	})
}

func TestIPCond(t *testing.T) {
	testCases := []struct {
		Name    string
		Cond    Cond
		Packet  *Packet
		ExpEval bool
	}{
		{
			Name: "Match IPv4 destination",
			Cond: NewCondAllOf(
				NewCondIPv4(
					&IPv4MatchDestination{
						&net.IPNet{
							IP:   net.IP{192, 168, 1, 0},
							Mask: net.IPv4Mask(255, 255, 255, 240),
						},
					},
				),
			),
			Packet: newTestPacket(
				&layers.IPv4{
					SrcIP: net.IP{172, 17, 1, 1},
					DstIP: net.IP{192, 168, 1, 2},
				},
				[]byte{1, 1, 1, 1},
			),
			ExpEval: true,
		},
		{
			Name: "Match IP source but not ToS",
			Cond: NewCondAllOf(
				NewCondIPv4(
					&IPv4MatchToS{
						TOS: 0x80,
					},
				),
				NewCondIPv4(
					&IPv4MatchSource{
						&net.IPNet{
							IP:   net.IP{192, 168, 1, 1},
							Mask: net.IPv4Mask(255, 255, 255, 255),
						},
					},
				),
			),
			Packet: newTestPacket(
				&layers.IPv4{
					SrcIP: net.IP{192, 168, 1, 1},
					DstIP: net.IP{10, 0, 0, 2},
				},
				[]byte{2, 2, 2, 2},
			),
			ExpEval: false,
		},
	}

	Convey("TestIPCond", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				SoMsg("eval", tc.Cond.Eval(tc.Packet), ShouldEqual, tc.ExpEval)
			})
		}
	})
}

func newTestPacket(ipv4 *layers.IPv4, pld []byte) *Packet {
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{},
		ipv4,
		gopacket.Payload(pld),
	)
	return NewPacket(buf.Bytes())
}
