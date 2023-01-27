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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/tools/braccept/runner"
)

// SCMPUnknownHop tests a packet with a wrong ingress interface ID.
func SCMPUnknownHop(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13},
		EthernetType: layers.EthernetTypeIPv4,
	}
	// IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 13, 3},
		DstIP:    net.IP{192, 168, 13, 2},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	// UDP: Src=40000 Dst=50000
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(40000),
		DstPort: layers.UDPPort(50000),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// pkt0.ParsePacket(`
	//	SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
	//		ADDR: SrcIA=1-ff00:0:3 Src=174.16.3.1 DstIA=1-ff00:0:4 Dst=174.16.4.1
	//		IF_1: ISD=1 Hops=3 Flags=ConsDir
	//			HF_1: ConsIngress=0 ConsEgress=311
	//			HF_2: ConsIngress=131 ConsEgress=141
	//			HF_3: ConsIngress=411 ConsEgress=0
	//	UDP_1: Src=40111 Dst=40222
	// `)
	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 311},
			{ConsIngress: 404, ConsEgress: 141},
			{ConsIngress: 411, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        xtest.MustParseIA("1-ff00:0:3"),
		DstIA:        xtest.MustParseIA("1-ff00:0:4"),
		Path:         sp,
	}
	srcA := &net.IPAddr{IP: net.ParseIP("172.16.3.1").To4()}
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(&net.IPAddr{IP: net.ParseIP("174.16.4.1").To4()}); err != nil {
		panic(err)
	}

	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 40111
	scionudp.DstPort = 40222
	scionudp.SetNetworkLayerForChecksum(scionL)

	payload := []byte("actualpayloadbytes")
	pointer := slayers.CmnHdrLen + scionL.AddrHdrLen() +
		(4 + 8*sp.NumINF + 12*int(sp.PathMeta.CurrHF))

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	// Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	// 	IP4: Src=192.168.14.2 Dst=192.168.13.3 Checksum=0
	ip.SrcIP = net.IP{192, 168, 13, 2}
	ip.DstIP = net.IP{192, 168, 13, 3}
	// 	UDP: Src=50000 Dst=40000
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	scionL.DstIA = scionL.SrcIA
	scionL.SrcIA = xtest.MustParseIA("1-ff00:0:1")
	if err := scionL.SetDstAddr(srcA); err != nil {
		panic(err)
	}
	intlA := &net.IPAddr{IP: net.IP{192, 168, 0, 11}}
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
	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeUnknownHopFieldIngress),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPParameterProblem{
		Pointer: uint16(pointer),
	}

	// Skip Ethernet + IPv4 + UDP
	quoteStart := 14 + 20 + 8
	quote := input.Bytes()[quoteStart:]
	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP, gopacket.Payload(quote),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPUnknownHop",
		WriteTo:         "veth_131_host",
		ReadFrom:        "veth_131_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPUnknownHop"),
		NormalizePacket: scmpNormalizePacket,
	}
}

// SCMPUnknownHopEgress sends a packet for an egress interface that doesn't
// exists.
func SCMPUnknownHopEgress(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13},
		EthernetType: layers.EthernetTypeIPv4,
	}
	// IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 13, 3},
		DstIP:    net.IP{192, 168, 13, 2},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	// UDP: Src=40000 Dst=50000
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(40000),
		DstPort: layers.UDPPort(50000),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
	// 		ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:f1 Dst=172.16.16.1
	// 		IF_1: ISD=1 Hops=3 Flags=ConsDir
	//			HF_1: ConsIngress=0 ConsEgress=311
	//			HF_2: ConsIngress=131 ConsEgress=611
	//			HF_3: ConsIngress=161 ConsEgress=0
	// UDP_1: Src=40111 Dst=40222
	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 311},
			{ConsIngress: 131, ConsEgress: 611},
			{ConsIngress: 161, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        xtest.MustParseIA("1-ff00:0:3"),
		DstIA:        xtest.MustParseIA("1-ff00:0:f1"),
		Path:         sp,
	}
	srcA := &net.IPAddr{IP: net.ParseIP("172.16.3.1")}
	dstA := &net.IPAddr{IP: net.ParseIP("174.16.16.1")}
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(dstA); err != nil {
		panic(err)
	}

	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 40111
	scionudp.DstPort = 40222
	scionudp.SetNetworkLayerForChecksum(scionL)

	payload := []byte("actualpayloadbytes")
	pointer := slayers.CmnHdrLen + scionL.AddrHdrLen() +
		(4 + 8*sp.NumINF + 12*int(sp.PathMeta.CurrHF))

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	// Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x13}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	// 	IP4: Src=192.168.14.2 Dst=192.168.13.3 Checksum=0
	ip.SrcIP = net.IP{192, 168, 13, 2}
	ip.DstIP = net.IP{192, 168, 13, 3}
	// 	UDP: Src=50000 Dst=40000
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	scionL.DstIA = scionL.SrcIA
	scionL.SrcIA = xtest.MustParseIA("1-ff00:0:1")
	if err := scionL.SetDstAddr(srcA); err != nil {
		panic(err)
	}
	intlA := &net.IPAddr{IP: net.IP{192, 168, 0, 11}}
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
	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeUnknownHopFieldEgress),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPParameterProblem{Pointer: uint16(pointer)}

	// Skip Ethernet + IPv4 + UDP
	quoteStart := 14 + 20 + 8
	quote := input.Bytes()[quoteStart:]
	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP, gopacket.Payload(quote),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPUnknownHopEgress",
		WriteTo:         "veth_131_host",
		ReadFrom:        "veth_131_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPUnknownHopEgress"),
		NormalizePacket: scmpNormalizePacket,
	}
}
