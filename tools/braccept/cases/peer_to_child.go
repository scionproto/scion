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

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/tools/braccept/runner"
)

// PeerToChild tests transit traffic over one BR host and one peering hop.
// In this case, traffic enters via a peering link, and leaves via a regular link from
// the same router. To be valid, the path as to be constructed as one up
// segment ending at the peering link's origin and one down segment over
// the regular link. The peering hop is the first hop on the second segment as
// it crosses from a peering interface to a child interface.
// In this test case, the up segment is a one-hop segment. The peering link's
// origin is the only hop.
func PeerToChild(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// We inject the packet into A (at IF 121) as if coming from 2 (at IF 211)
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}, // IF 211
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x12}, // IF 121
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{ // On the 2->A link
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 12, 3}, // from 2's 211 IP
		DstIP:    net.IP{192, 168, 12, 2}, // to A's 121 IP
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
				CurrINF: 1,
				SegLen:  [3]uint8{1, 2, 0},
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
			},
			// down seg
			{
				SegID:     0x222,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
				Peer:      true,
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 211, ConsEgress: 0},   // at 2 out to A
			{ConsIngress: 121, ConsEgress: 151}, // at A in from 2 out to 5
			{ConsIngress: 511, ConsEgress: 0},   // at 5 in from A
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

	// HF[0] is a regular hop.
	sp.HopFields[0].Mac = path.MAC(macGenX, sp.InfoFields[0], sp.HopFields[0], nil)

	// HF[1] is a peering hop so it has the same SegID acc value as the next one
	// in construction direction, HF[2]. That is, SEG[1]'s SegID.
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[1], nil)
	sp.HopFields[2].Mac = path.MAC(macGenY, sp.InfoFields[1], sp.HopFields[2], nil)

	// The message if ready for ingest at A, that is at HF[1], the start of the
	// second segment, in construction direction. So SegID is already correct.

	// The end-to-end trip is from  2,172.16.2.1 to 5,172.16.5.1
	// That won't change through forwarding.
	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:2"),
		DstIA:        addr.MustParseIA("1-ff00:0:5"),
		Path:         sp,
	}
	if err := scionL.SetSrcAddr(addr.MustParseHost("172.16.2.1")); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.5.1")); err != nil {
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
	// We expect it out of A's 151 IF on its way to 5's 511 IF.

	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x15} // IF 151
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef} // IF 511
	ip.SrcIP = net.IP{192, 168, 15, 2}                                     // from A's 151 IP
	ip.DstIP = net.IP{192, 168, 15, 3}                                     // to 5's 511 IP
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	// Out of A, the current segment is seg 1. The Current acc
	// value is still the same since HF[1] is a peering hop.

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "ChildToChildPeeringTransit",
		WriteTo:  "veth_121_host", // Where we inject the test packet
		ReadFrom: "veth_151_host", // Where we capture the forwarded packet
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "ChildToChildXover"),
	}
}
