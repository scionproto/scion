// Copyright 2023 SCION Association
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
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// Topology (see accept/router_newbenchmark/conf/topology.json)
//    AS2 (br2) ---+== (br1a) AS1 (br1b) ---- (br4) AS4
//                 |
//    AS3 (br3) ---+
// See topo.go

// oneBrTransit generates one packet of transit traffic over the same BR host.
// The outcome is a raw packet.
func oneBrTransit(payload string, mac hash.Hash, flowId uint32) []byte {

	var (
		originIA   = isdAS(2)
		originIP   = publicIP(2, 1)
		originHost = hostAddr(originIP)
		srcIP      = publicIP(2, 1)
		srcMAC     = macAddr(srcIP)
		dstIP      = publicIP(1, 2)
		dstMAC     = macAddr(dstIP)
		targetIA   = isdAS(3)
		targetIP   = publicIP(3, 1)
		targetHost = hostAddr(targetIP)
	)

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Point-to-point.
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
		SrcIP:    srcIP.AsSlice(),
		DstIP:    dstIP.AsSlice(),
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
	if err := scionL.SetSrcAddr(originHost); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(targetHost); err != nil {
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

// BrTransit generates numDistinct packets (each with a unique flowID) with the given payload
// constructed to cause br_transit traffic at the br1a router.
// numDistrinct is a small number, only to enable multiple parallel streams. Each distinct packet
// is meant to be replayed a large number of times for performance measurement.
func BrTransit(payload string, mac hash.Hash, numDistinct int) (string, string, [][]byte) {
	packets := make([][]byte, numDistinct)
	for i := 0; i < numDistinct; i++ {
		packets[i] = oneBrTransit(payload, mac, uint32(i+1))
	}
	return interfaceName(1, 2), interfaceName(1, 3), packets
}
