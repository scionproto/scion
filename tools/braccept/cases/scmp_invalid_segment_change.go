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

// SCMPParentToParentXover tests a packet that attempts a segment switch from a
// down segment to a up segment. The egress interface is on a different router
// than the ingress interface.
func SCMPParentToParentXover(artifactsDir string, mac hash.Hash) runner.Case {
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
				CurrHF:  1,
				CurrINF: 0,
				SegLen:  [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path.InfoField{
			// down seg
			{
				SegID:     0x111,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
			// up seg
			{
				SegID:     0x222,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 311},
			{ConsIngress: 131, ConsEgress: 0},
			{ConsIngress: 191, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 911},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.HopFields[2].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[2], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:3"),
		DstIA:        addr.MustParseIA("1-ff00:0:9"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("172.16.5.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
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

	// Prepare quoted packet that is part of the SCMP error message.
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	quoted := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(quoted, options,
		scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}
	quote := quoted.Bytes()

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	ip.SrcIP = net.IP{192, 168, 13, 2}
	ip.DstIP = net.IP{192, 168, 13, 3}
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	scionL.DstIA = scionL.SrcIA
	scionL.SrcIA = addr.MustParseIA("1-ff00:0:1")
	if err := scionL.SetDstAddr(srcA); err != nil {
		panic(err)
	}
	intlA := addr.MustParseHost("192.168.0.11")
	if err := scionL.SetSrcAddr(intlA); err != nil {
		panic(err)
	}

	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	scionL.NextHdr = slayers.End2EndClass
	e2e := normalizedSCMPPacketAuthEndToEndExtn()
	e2e.NextHdr = slayers.L4SCMP
	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidSegmentChange,
		),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)

	// The pointer should point to the info field of the segment that is switched to.
	pointer := slayers.CmnHdrLen + scionL.AddrHdrLen() + scion.MetaLen + path.InfoLen
	scmpP := &slayers.SCMPParameterProblem{
		Pointer: uint16(pointer),
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP, gopacket.Payload(quote),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPParentToParentXover",
		WriteTo:         "veth_131_host",
		ReadFrom:        "veth_131_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPParentToParentXover"),
		NormalizePacket: scmpNormalizePacket,
	}
}

// SCMPParentToChildXover tests a packet that attempts a segment switch from a
// down segment to another down segment. The egress interface is on a different
// router than the ingress interface.
func SCMPParentToChildXover(artifactsDir string, mac hash.Hash) runner.Case {
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
				CurrHF:  1,
				CurrINF: 0,
				SegLen:  [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path.InfoField{
			// down seg
			{
				SegID:     0x111,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
			// even more down seg
			{
				SegID:     0x222,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 311},
			{ConsIngress: 131, ConsEgress: 0},
			{ConsIngress: 131, ConsEgress: 181},
			{ConsIngress: 811, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.HopFields[2].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[2], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:3"),
		DstIA:        addr.MustParseIA("1-ff00:0:8"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("172.16.5.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
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

	// Prepare quoted packet that is part of the SCMP error message.
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	quoted := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(quoted, options,
		scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}
	quote := quoted.Bytes()

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	ip.SrcIP = net.IP{192, 168, 13, 2}
	ip.DstIP = net.IP{192, 168, 13, 3}
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	scionL.DstIA = scionL.SrcIA
	scionL.SrcIA = addr.MustParseIA("1-ff00:0:1")
	if err := scionL.SetDstAddr(srcA); err != nil {
		panic(err)
	}
	intlA := addr.MustParseHost("192.168.0.11")
	if err := scionL.SetSrcAddr(intlA); err != nil {
		panic(err)
	}

	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	scionL.NextHdr = slayers.End2EndClass
	e2e := normalizedSCMPPacketAuthEndToEndExtn()
	e2e.NextHdr = slayers.L4SCMP
	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidSegmentChange,
		),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)

	// The pointer should point to the info field of the segment that is
	// switched to.
	pointer := slayers.CmnHdrLen + scionL.AddrHdrLen() + scion.MetaLen + path.InfoLen
	scmpP := &slayers.SCMPParameterProblem{
		Pointer: uint16(pointer),
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP, gopacket.Payload(quote),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPParentToChildXover",
		WriteTo:         "veth_131_host",
		ReadFrom:        "veth_131_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPParentToChildXover"),
		NormalizePacket: scmpNormalizePacket,
	}
}

// SCMPChildToParentXover tests a packet that attempts a segment switch from an
// up segment to another up segment. The egress interface is on a different
// router than the ingress interface.
func SCMPChildToParentXover(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x14},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 14, 3},
		DstIP:    net.IP{192, 168, 14, 2},
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
				SegLen:  [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path.InfoField{
			// up seg
			{
				SegID:     0x111,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
			// even more up seg
			{
				SegID:     0x222,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 411, ConsEgress: 0},
			{ConsIngress: 131, ConsEgress: 141},
			{ConsIngress: 191, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 911},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
	sp.HopFields[2].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[2], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:4"),
		DstIA:        addr.MustParseIA("1-ff00:0:9"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("172.16.5.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
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

	// Prepare quoted packet that is part of the SCMP error message.
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	quoted := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(quoted, options,
		scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}
	quote := quoted.Bytes()

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x14}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	ip.SrcIP = net.IP{192, 168, 14, 2}
	ip.DstIP = net.IP{192, 168, 14, 3}
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	scionL.DstIA = scionL.SrcIA
	scionL.SrcIA = addr.MustParseIA("1-ff00:0:1")
	if err := scionL.SetDstAddr(srcA); err != nil {
		panic(err)
	}
	intlA := addr.MustParseHost("192.168.0.11")
	if err := scionL.SetSrcAddr(intlA); err != nil {
		panic(err)
	}

	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	scionL.NextHdr = slayers.End2EndClass
	e2e := normalizedSCMPPacketAuthEndToEndExtn()
	e2e.NextHdr = slayers.L4SCMP
	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidSegmentChange,
		),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)

	// The pointer should point to the info field of the segment that is switched to.
	pointer := slayers.CmnHdrLen + scionL.AddrHdrLen() + scion.MetaLen + path.InfoLen
	scmpP := &slayers.SCMPParameterProblem{
		Pointer: uint16(pointer),
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP, gopacket.Payload(quote),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPChildToParentXover",
		WriteTo:         "veth_141_host",
		ReadFrom:        "veth_141_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPChildToParentXover"),
		NormalizePacket: scmpNormalizePacket,
	}
}

// SCMPInternalXover tests a packet that attempts a segment switch but was
// received on the internal interface. That is never allowed.
func SCMPInternalXover(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x1},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 0, 13},
		DstIP:    net.IP{192, 168, 0, 11},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(30003),
		DstPort: layers.UDPPort(30001),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF:  1,
				CurrINF: 0,
				SegLen:  [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path.InfoField{
			// down seg (reversed)
			{
				SegID:     0x222,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
			// up seg (reversed)
			{
				SegID:     0x111,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 811, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 181},
			{ConsIngress: 0, ConsEgress: 141},
			{ConsIngress: 411, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	// sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
	sp.HopFields[2].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[2], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4SCMP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:8"),
		DstIA:        addr.MustParseIA("1-ff00:0:4"),
		Path:         sp,
	}

	srcA := addr.MustParseHost("172.168.0.14")
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	dstA := addr.MustParseHost("172.16.4.1")
	if err := scionL.SetDstAddr(dstA); err != nil {
		panic(err)
	}

	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPTraceroute{
		Identifier: 558,
		Sequence:   130,
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	// Prepare quoted packet that is part of the SCMP error message.
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	quoted := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(quoted, options,
		scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}
	quote := quoted.Bytes()

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x1}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	scionL.DstIA = scionL.SrcIA
	scionL.SrcIA = addr.MustParseIA("1-ff00:0:1")
	if err := scionL.SetDstAddr(srcA); err != nil {
		panic(err)
	}
	intlA := addr.MustParseHost("192.168.0.11")
	if err := scionL.SetSrcAddr(intlA); err != nil {
		panic(err)
	}

	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	scionL.NextHdr = slayers.End2EndClass
	e2e := normalizedSCMPPacketAuthEndToEndExtn()
	e2e.NextHdr = slayers.L4SCMP
	scmpH = &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidSegmentChange,
		),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)

	// The pointer should point to the info field of the segment that is switched to.
	pointer := slayers.CmnHdrLen + scionL.AddrHdrLen() + scion.MetaLen + path.InfoLen
	scmpReplyP := &slayers.SCMPParameterProblem{
		Pointer: uint16(pointer),
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpReplyP, gopacket.Payload(quote),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPInternalXover",
		WriteTo:         "veth_int_host",
		ReadFrom:        "veth_int_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPInternalXover"),
		NormalizePacket: scmpNormalizePacket,
	}
}
