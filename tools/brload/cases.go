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

// Topology (see accept/router_newbenchmark/conf/topology.json)
//    AS2 (br2) ---+== (br1a) AS1 (br1b) ---- (br4) AS4
//                 |
//    AS3 (br3) ---+
//
// We're only executing and monitoring br1a. All the others are a fiction (except for the knowledge
// about them configured in br1a) from which we construct packets that get injected at one of the
// br1a interfaces.
//
// In the tests cases, the various addresses used to construct packets are:
// originIA: the ISD/AS number of the AS of the initial sender.
// originIP: the underlay address (and so SCION host) of the initial sender.
// srcIP: the IP address of the router interface sending to br1a.
// srcMac: the ethernet address of the router interface sending to br1a.
// dstIP: the IP address of the br1a interface that should receives the packet.
// dstMac: the ethernet address of the br1a interface that should receive the packet.
// targetIA: the ISD/AS number of the AS of the final recipient.
// targetIP: the underlay address (and so SCION host) of the final recipient.
//
// To further simplify the explicit configuration that we need, the topology follows a convention
// to assign addresses, so that an address can be inferred from a single node and interface number.
// ISD/AS: <1 or 2>-ff00:0:<AS index>
// interface number: <remote AS index>
// public IP address: 192.168.<AS_1's interface number>.<local AS index>
// internal IP address: 192.168.0.<router index>
// MAC Address: 0xf0, 0x0d, 0xfe, 0xbe, <last two bytes of IP>
// Internal port: 30042
// External port: 50000
// As a result, children ASes (like AS2) have addresses ending in N.N and interface N where N is
// the AS number. For br1a/b, interfaces are numbered after the child on the other side, the
// public IPS are <childAS>.1 and the internal IP ends in 0.1 or 0.2. The MAC addresses follow.

// TODO: add functions that produce the right numbers from an intuitive descriptor.

// oneBrTransit generates one packet of transit traffic over the same BR host.
// The outcome is a raw packet.
func oneBrTransit(payload string, mac hash.Hash, flowId uint32) []byte {

	var (
		originIA = xtest.MustParseIA("1-ff00:0:2")
		originIP = "192.168.2.2"
		srcIP    = net.IP{192, 168, 2, 2}
		srcMAC   = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x02, 0x02}
		dstIP    = net.IP{192, 168, 2, 1}
		dstMAC   = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x02, 0x01}
		targetIP = "192.168.3.3"
		targetIA = xtest.MustParseIA("1-ff00:0:3")
	)

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Point-to-point. Src might not mater. Dst probably must match what test.py configured
	// for interface 2 of the router.
	ethernet := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Point-to-point. This is the real IP: the underlay network.
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
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
		FlowID:       flowId,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        originIA,
		DstIA:        targetIA,
		Path:         sp,
	}

	// These aren't necessarily IP addresses. They're host addresses within the
	// src and dst ASes.
	if err := scionL.SetSrcAddr(addr.MustParseHost(originIP)); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost(targetIP)); err != nil {
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
	return input.Bytes()
}

func BrTransit(payload string, mac hash.Hash, numDistinct int) (string, string, [][]byte) {
	packets := make([][]byte, numDistinct, numDistinct)
	for i := 0; i < numDistinct; i++ {
		packets[i] = oneBrTransit(payload, mac, uint32(i+1))
	}
	return "veth_2_host", "veth_3_host", packets
}
