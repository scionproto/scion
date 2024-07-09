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

package cases

import (
	"hash"
	"net"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/tools/braccept/runner"
)

// ChildToPeer tests transit traffic over one BR host and one peering hop.
// In this case, traffic enters via a regular link, and leaves via a peering link from
// the same router. To be valid, the path as to be constructed as one up segment over
// the normal link ending with a peering hop and one down segment starting at the
// peering link's destination. The peering hop is the second hop on the first segment
// as it crosses from a child interface to a peering interface.
// In this test case, the down segment is a one-hop segment. The peering link's destination
// is the only hop.
func ChildToPeer(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// We inject the packet into A (at IF 151) as if coming from 5 (at IF 511)
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}, // IF 511
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x15}, // IF 151
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{ // On the 5->A link
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 15, 3}, // from 5's 511 IP
		DstIP:    net.IP{192, 168, 15, 2}, // to A's 151 IP
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(40000),
		DstPort: layers.UDPPort(50000),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF:  1,
				CurrINF: 0,
				SegLen:  [3]uint8{2, 1, 0},
			},
			NumINF:  2,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			// up seg
			{
				SegID:     0x111,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
				Peer:      true,
			},
			// down seg
			{
				SegID:     0x222,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 511, ConsEgress: 0},   // at 5 leaving to A
			{ConsIngress: 121, ConsEgress: 151}, // at A in from 5 out to 2
			{ConsIngress: 211, ConsEgress: 0},   // at 2 in coming from A
		},
	}

	// Make the packet look the way it should... We have three hops of interrest.

	// Hops are all signed with different keys. Only HF[1] was signed by
	// the AS that we hand the packet to. The others can be anything as they
	// couldn't be check at that AS anyway.
	macGenX, err := scrypto.InitMac([]byte("1234567812345678"))
	if err != nil {
		panic(err)
	}
	macGenY, err := scrypto.InitMac([]byte("abcdefghabcdefgh"))
	if err != nil {
		panic(err)
	}

	// HF[1] is a peering hop, so it has the same SegID acc value as the next one
	// in construction direction, HF[0]. That is, SEG[0]'s SegID.
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.HopFields[0].Mac = path.MAC(macGenX, sp.InfoFields[0], sp.HopFields[0], nil)

	// The second segment has just one hop.
	sp.HopFields[2].Mac = path.MAC(macGenY, sp.InfoFields[1], sp.HopFields[2], nil)

	// The message is ready for ingest at A, that is at HF[1]. Going against consruction
	// direction, the SegID acc value must match that of HF[0], which is the same
	// as that of HF[1], which is also SEG[0]'s SegID. So it's already correct.

	// The end-to-end trip is from 5,172.16.5.1 to 2,172.16.2.1
	// That won't change through forwarding.
	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:5"),
		DstIA:        addr.MustParseIA("1-ff00:0:2"),
		Path:         sp,
	}
	if err := scionL.SetSrcAddr(addr.MustParseHost("172.16.5.1")); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.2.1")); err != nil {
		panic(err)
	}

	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 40111
	scionudp.DstPort = 40222
	scionudp.SetNetworkLayerForChecksum(scionL)

	payload := []byte("actualpayloadbytes")

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	// Prepare want packet
	// We expect it out of A's 121 IF on its way to 4's 211 IF.

	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x12} // IF 121
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef} // IF 211
	ip.SrcIP = net.IP{192, 168, 12, 2}                                     // from A's 121 IP
	ip.DstIP = net.IP{192, 168, 12, 3}                                     // to 2's 211 IP
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	// Out of A, the current segment is seg 1. The Current acc
	// value matches HF[2], which is SEG[1]'s SegID since HF[2] is the first hop in
	// construction direction of the segment.

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "ChildToChildPeeringOut",
		WriteTo:  "veth_151_host", // Where we inject the test packet
		ReadFrom: "veth_121_host", // Where we capture the forwarded packet
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "ChildToChildXover"),
	}
}
