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

package main

import (
	"hash"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// BrTransit generates one packet of transit traffic over the same BR host.
// The outcome is a packet and which interface to send it to.
func BrTransit(payload string, mac hash.Hash) (string, string, []byte) {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Point-to-point. Src might not mater. Dst probably must match what test.py configured
	// for interface 2 of the router.
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Point-to-point. This is the real IP: the underlay network.
	// IP4: Src=192.168.2.2 Dst=192.168.2.1 NextHdr=UDP Flags=DF
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 2, 2},
		DstIP:    net.IP{192, 168, 2, 1},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	// 	UDP: Src=50000 Dst=50000
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(50000),
		DstPort: layers.UDPPort(50000),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// Fully correct path.
	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				Timestamp: util.TimeToSecs(time.Now()),
				ConsDir:   false,
			},
			{
				SegID:     0x222,
				Timestamp: util.TimeToSecs(time.Now()),
				ConsDir:   true,
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 22, ConsEgress: 0}, // From there (non-consdir)
			{ConsIngress: 0, ConsEgress: 2},  // <- Processed here (non-consdir)
			{ConsIngress: 0, ConsEgress: 3},  // Down via this
			{ConsIngress: 33, ConsEgress: 0}, // To there
		},
	}

	// Calculate MACs...
	// Seg0: Hops are in non-consdir.
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
	sp.HopFields[0].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[0], nil)

	// Seg1: in the natural order.
	sp.HopFields[2].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[2], nil)
	sp.InfoFields[1].UpdateSegID(sp.HopFields[2].Mac) // tmp
	sp.HopFields[3].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[2], nil)
	sp.InfoFields[1].SegID = 0x222 // Restore to initial.

	// End-to-end. Src is the originator and Dst is the final destination.
	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        xtest.MustParseIA("1-ff00:0:2"),
		DstIA:        xtest.MustParseIA("1-ff00:0:3"),
		Path:         sp,
	}

	// These aren't necessarily IP addresses. They're host addresses within the
	// src and dst ASes.
	if err := scionL.SetSrcAddr(addr.MustParseHost("192.168.2.2")); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("192.168.3.3")); err != nil {
		panic(err)
	}

	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 50000
	scionudp.DstPort = 50000
	scionudp.SetNetworkLayerForChecksum(scionL)

	payloadBytes := []byte(payload)

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payloadBytes),
	); err != nil {
		panic(err)
	}

	return "veth_2_host", "veth_3_host", input.Bytes()
}
