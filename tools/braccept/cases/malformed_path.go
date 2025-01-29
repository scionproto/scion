// Copyright 2024 SCION Association
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
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/tools/braccept/runner"
)

// MalformedPathSingletonSegment tests invalid (non-peer) path segments with a single hop field.
// In this test case, an invalid single-hop core segment is included in an otherwise valid path.
// This is invalid and the semantics of this are consequently undefined; in our implementation of
// the router, this specific case would result in the same effective path as without the core
// segment, with both the ingress _and_ the egress router performing a segment cross over
// (https://github.com/scionproto/scion/issues/4524).
func MalformedPathSingletonSegment(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x15},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 15, 3},
		DstIP:    net.IP{192, 168, 15, 2},
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
				SegLen:  [3]uint8{2, 1, 2},
			},
			NumINF:  3,
			NumHops: 5,
		},
		InfoFields: []path.InfoField{
			// up seg
			{
				SegID:     0x111,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
			// core seg
			{
				SegID:     0x333,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
			// down seg
			{
				SegID:     0x222,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 511, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 151}, // \
			{ConsIngress: 141, ConsEgress: 0}, // | ff00:0:1
			{ConsIngress: 0, ConsEgress: 141}, // /
			{ConsIngress: 411, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
	sp.HopFields[2].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[2], nil)
	sp.HopFields[3].Mac = path.MAC(mac, sp.InfoFields[2], sp.HopFields[3], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:5"),
		DstIA:        addr.MustParseIA("1-ff00:0:4"),
		Path:         sp,
	}

	if err := scionL.SetSrcAddr(addr.MustParseHost("172.16.5.1")); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.4.1")); err != nil {
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

	return runner.Case{
		Name:     "MalformedPathSingletonSegment",
		WriteTo:  "veth_151_host",
		ReadFrom: "no_pkt_expected",
		Input:    input.Bytes(),
		Want:     nil,
		StoreDir: filepath.Join(artifactsDir, "MalformedPathSingletonSegment"),
	}
}

// MalformedPathCurrHFNotInCurrINF tests an invalid combination of CurrHF and CurrINF
func MalformedPathCurrHFNotInCurrINF(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 13, 3},
		DstIP:    net.IP{192, 168, 13, 2},
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
				CurrINF: 0, // BAD! CurrHF points into second segment (CurrINF=1)
				CurrHF:  3,
				SegLen:  [3]uint8{2, 3, 0},
			},
			NumINF:  2,
			NumHops: 5,
		},
		InfoFields: []path.InfoField{
			// core segment
			{
				SegID:     0x222,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
			// down segment
			{
				SegID:     0x111,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 1337},
			{ConsIngress: 4242, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 311},
			{ConsIngress: 131, ConsEgress: 151},
			{ConsIngress: 511, ConsEgress: 0},
		},
	}

	// Set up impossible/wrong MAC for current HF, so the MAC is valid for in the _wrong_ segment.
	// This ensures that the check for the valid CurrHF / CurrINF applies independent of the MAC
	// validation.
	sp.HopFields[3].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[3], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("2-ff00:0:42"),
		DstIA:        addr.MustParseIA("1-ff00:0:5"),
		Path:         sp,
	}
	if err := scionL.SetSrcAddr(addr.MustParseHost("172.16.3.1")); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("172.16.5.1")); err != nil {
		panic(err)
	}

	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 2354
	scionudp.DstPort = 21000
	scionudp.SetNetworkLayerForChecksum(scionL)

	payload := []byte("actualpayloadbytes")

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "MalformedPathCurrHFNotInCurrINF",
		WriteTo:  "veth_131_host",
		ReadFrom: "no_pkt_expected",
		Input:    input.Bytes(),
		Want:     nil,
		StoreDir: filepath.Join(artifactsDir, "MalformedPathCurrHFNotInCurrINF"),
	}
}
