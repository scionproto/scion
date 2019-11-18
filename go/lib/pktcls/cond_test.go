// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package pktcls_test

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/pktcls"
)

func TestBasicCond(t *testing.T) {
	testCases := []struct {
		Name    string
		Cond    pktcls.Cond
		ExpEval bool
	}{
		{
			Name:    "Any()",
			Cond:    pktcls.NewCondAnyOf(),
			ExpEval: true,
		},
		{
			Name:    "Any(True)",
			Cond:    pktcls.NewCondAnyOf(pktcls.CondTrue),
			ExpEval: true,
		},
		{
			Name:    "Any(False)",
			Cond:    pktcls.NewCondAnyOf(pktcls.CondFalse),
			ExpEval: false,
		},
		{
			Name:    "Any(False, True, False)",
			Cond:    pktcls.NewCondAnyOf(pktcls.CondFalse, pktcls.CondTrue, pktcls.CondFalse),
			ExpEval: true,
		},
		{
			Name:    "All()",
			Cond:    pktcls.NewCondAllOf(),
			ExpEval: true,
		},
		{
			Name:    "All(True)",
			Cond:    pktcls.NewCondAllOf(pktcls.CondTrue),
			ExpEval: true,
		},
		{
			Name:    "All(False)",
			Cond:    pktcls.NewCondAllOf(pktcls.CondFalse),
			ExpEval: false,
		},
		{
			Name:    "All(False, True, False)",
			Cond:    pktcls.NewCondAllOf(pktcls.CondFalse, pktcls.CondTrue, pktcls.CondFalse),
			ExpEval: false,
		},
		{
			Name: "All(Any(), All(), False)",
			Cond: pktcls.NewCondAllOf(pktcls.NewCondAnyOf(),
				pktcls.NewCondAllOf(), pktcls.CondFalse),
			ExpEval: false,
		},
		{
			Name: "All(Any(), All(), Not(Not(True)))",
			Cond: pktcls.NewCondAllOf(pktcls.NewCondAnyOf(), pktcls.NewCondAllOf(),
				pktcls.NewCondNot(pktcls.NewCondNot(pktcls.CondTrue))),
			ExpEval: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			assert.Equal(t, test.ExpEval, test.Cond.Eval(nil))
		})
	}
}

func TestIPCond(t *testing.T) {
	testCases := []struct {
		Name    string
		Cond    pktcls.Cond
		Packet  *pktcls.Packet
		ExpEval bool
	}{
		{
			Name: "Match IPv4 destination",
			Cond: pktcls.NewCondAllOf(
				pktcls.NewCondIPv4(
					&pktcls.IPv4MatchDestination{
						Net: &net.IPNet{
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
			Cond: pktcls.NewCondAllOf(
				pktcls.NewCondIPv4(
					&pktcls.IPv4MatchToS{
						TOS: 0x80,
					},
				),
				pktcls.NewCondIPv4(
					&pktcls.IPv4MatchSource{
						Net: &net.IPNet{
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

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			assert.Equal(t, test.ExpEval, test.Cond.Eval(test.Packet))
		})
	}
}

func TestStringer(t *testing.T) {
	_, net, _ := net.ParseCIDR("12.12.12.0/26")
	tests := map[string]struct {
		Cond pktcls.Cond
		Str  string
	}{
		"AllAnyNot": {
			Str: "all(any(BOOL=true),all(BOOL=false),not(not(BOOL=true)))",
			Cond: pktcls.NewCondAllOf(
				pktcls.NewCondAnyOf(pktcls.CondTrue),
				pktcls.NewCondAllOf(pktcls.CondFalse),
				pktcls.NewCondNot(pktcls.NewCondNot(pktcls.CondTrue)),
			),
		},
		"ANY ALL NOT src dst dscp tos": {
			Str: "any(dscp=0x2,all(dst=12.12.12.0/26,tos=0x2,not(src=12.12.12.0/26)))",
			Cond: pktcls.CondAnyOf{
				pktcls.NewCondIPv4(&pktcls.IPv4MatchDSCP{DSCP: uint8(0x2)}),
				pktcls.CondAllOf{
					pktcls.NewCondIPv4(&pktcls.IPv4MatchDestination{Net: net}),
					pktcls.NewCondIPv4(&pktcls.IPv4MatchToS{TOS: uint8(0x2)}),
					pktcls.CondNot{Operand: pktcls.NewCondIPv4(
						&pktcls.IPv4MatchSource{Net: net},
					)},
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			strCond := test.Cond.String()
			assert.Equal(t, test.Str, strCond)
			parsedCond, err := pktcls.BuildClassTree(strCond)
			assert.NoError(t, err)
			assert.Equal(t, test.Cond, parsedCond)
		})
	}
}

func newTestPacket(ipv4 *layers.IPv4, pld []byte) *pktcls.Packet {
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{},
		ipv4,
		gopacket.Payload(pld),
	)
	return pktcls.NewPacket(buf.Bytes())
}
