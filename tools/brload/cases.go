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

	// Ethernet: these addresses don't matter. The interfaces are not actually created.
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x01, 0x01},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x01, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	// These do mater. They're known neighbors of our router under test. See
	// router_newbenchmark/topology.json.
	// IP4: Src=192.168.2.2 Dst=192.168.2.3 NextHdr=UDP Flags=DF
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 2, 2},
		DstIP:    net.IP{192, 168, 3, 3},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	// 	UDP: Src=50000 Dst=50000
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(50000),
		DstPort: layers.UDPPort(50000),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// pkt0.ParsePacket(`
	// 	SCION: NextHdr=UDP CurrInfoF=0 CurrHopF=1 SrcType=IPv4 DstType=IPv4
	// 		ADDR: SrcIA=1-ff00:0:2 Src=192.168.2.2 DstIA=1-ff00:0:3 Dst=192.168.3.3
	// 		IF_2: ISD=1 Hops=2 Flags=non-ConsDir
	// 			HF_1: ConsIngress=0 ConsEgress=0
	// 			HF_0: ConsIngress=131 ConsEgress=141
	// 	UDP_1: Src=40111 Dst=40222
	// `)
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
		},
		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 2},  // Processed here (non-consdir)
			{ConsIngress: 22, ConsEgress: 0}, // From there (non-consdir)
			{ConsIngress: 0, ConsEgress: 3},  // Down via this
			{ConsIngress: 33, ConsEgress: 0}, // To there
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)

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
	if err := scionL.SetSrcAddr(addr.MustParseHost("192.168.2.2")); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("182.168.3.3")); err != nil {
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
