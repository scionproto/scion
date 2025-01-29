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
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/spao"
	"github.com/scionproto/scion/private/drkey/drkeyutil"
	"github.com/scionproto/scion/tools/braccept/runner"
)

// SCMPTracerouteIngress tests an SCMP traceroute request with alert on the
// ingress interface.
func SCMPTracerouteIngress(artifactsDir string, mac hash.Hash) runner.Case {
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
				CurrHF: 1,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 411, ConsEgress: 0},
			{ConsIngress: 121, ConsEgress: 141, EgressRouterAlert: true},
			{ConsIngress: 0, ConsEgress: 211},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4SCMP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:4"),
		DstIA:        addr.MustParseIA("1-ff00:0:2"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("172.16.4.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.2.1")); err != nil {
		panic(err)
	}

	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPTraceroute{
		Identifier: 567,
		Sequence:   129,
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
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

	sp.HopFields[1].EgressRouterAlert = false
	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}
	scionL.NextHdr = slayers.L4SCMP
	scmpH = &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP = &slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         scionL.SrcIA,
		Interface:  141,
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "SCMPTracerouteIngress",
		WriteTo:  "veth_141_host",
		ReadFrom: "veth_141_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "SCMPTracerouteIngress"),
	}
}

// SCMPTracerouteIngressWithSPAO tests an SCMP traceroute request with alert on the
// ingress interface and a SPAO header.
func SCMPTracerouteIngressWithSPAO(artifactsDir string, mac hash.Hash) runner.Case {
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
				CurrHF: 1,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 411, ConsEgress: 0},
			{ConsIngress: 121, ConsEgress: 141, EgressRouterAlert: true},
			{ConsIngress: 0, ConsEgress: 211},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.End2EndClass,
		HdrLen:       0x15,
		PayloadLen:   0x18,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:4"),
		DstIA:        addr.MustParseIA("1-ff00:0:2"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("172.16.4.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.2.1")); err != nil {
		panic(err)
	}

	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPTraceroute{
		Identifier: 567,
		Sequence:   129,
	}

	e2e := &slayers.EndToEndExtn{}

	sendTime := time.Now()
	key, err := (&drkeyutil.FakeProvider{
		EpochDuration:    drkeyutil.LoadEpochDuration(),
		AcceptanceWindow: drkeyutil.LoadAcceptanceWindow(),
	}).GetASHostKey(sendTime, addr.MustParseIA("1-ff00:0:4"), srcA)
	if err != nil {
		panic(err)
	}
	timestamp, err := spao.RelativeTimestamp(key.Epoch, sendTime)
	if err != nil {
		panic(err)
	}
	optAuth, err := slayers.NewPacketAuthOption(slayers.PacketAuthOptionParams{
		TimestampSN: timestamp,
		Auth:        make([]byte, 16),
	})
	if err != nil {
		panic(err)
	}
	e2e.Options = []*slayers.EndToEndOption{optAuth.EndToEndOption}
	e2e.NextHdr = slayers.L4SCMP
	e2ePayload := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		e2ePayload,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		scmpH,
		scmpP,
	)
	if err != nil {
		panic(err)
	}
	_, err = spao.ComputeAuthCMAC(
		spao.MACInput{
			Key:        key.Key[:],
			Header:     optAuth,
			ScionLayer: scionL,
			PldType:    slayers.L4SCMP,
			Pld:        e2ePayload.Bytes(),
		},

		make([]byte, spao.MACBufferSize),
		optAuth.Authenticator(),
	)
	if err != nil {
		panic(err)
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
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

	sp.HopFields[1].EgressRouterAlert = false
	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}
	scionL.NextHdr = slayers.End2EndClass
	spi, err := slayers.MakePacketAuthSPIDRKey(
		uint16(drkey.SCMP),
		slayers.PacketAuthASHost,
		slayers.PacketAuthSenderSide,
	)
	if err != nil {
		panic(err)
	}
	packAuthOpt, err := slayers.NewPacketAuthOption(slayers.PacketAuthOptionParams{
		SPI:         spi,
		Algorithm:   slayers.PacketAuthCMAC,
		TimestampSN: uint64(0),
		Auth:        make([]byte, 16),
	})
	if err != nil {
		panic(err)
	}
	e2e = &slayers.EndToEndExtn{
		Options: []*slayers.EndToEndOption{
			packAuthOpt.EndToEndOption,
		},
	}
	e2e.NextHdr = slayers.L4SCMP
	scmpH = &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP = &slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         scionL.SrcIA,
		Interface:  141,
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPTracerouteIngressWithSPAO",
		WriteTo:         "veth_141_host",
		ReadFrom:        "veth_141_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPTracerouteIngressWithSPAO"),
		NormalizePacket: scmpNormalizePacket,
	}
}

// SCMPTracerouteIngressConsDir tests an SCMP traceroute request with alert on the
// ingress interface.
func SCMPTracerouteIngressConsDir(artifactsDir string, mac hash.Hash) runner.Case {
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
			{ConsIngress: 131, ConsEgress: 141, IngressRouterAlert: true},
			{ConsIngress: 411, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4SCMP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:3"),
		DstIA:        addr.MustParseIA("1-ff00:0:4"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("172.16.3.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.4.1")); err != nil {
		panic(err)
	}

	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPTraceroute{
		Identifier: 567,
		Sequence:   129,
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
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
	scionL.SrcIA = addr.MustParseIA("1-ff00:0:1")
	if err := scionL.SetDstAddr(srcA); err != nil {
		panic(err)
	}
	intlA := addr.MustParseHost("192.168.0.11")
	if err := scionL.SetSrcAddr(intlA); err != nil {
		panic(err)
	}

	sp.HopFields[1].IngressRouterAlert = false
	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}
	scionL.NextHdr = slayers.L4SCMP
	scmpH = &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP = &slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         scionL.SrcIA,
		Interface:  131,
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "SCMPTracerouteIngressConsDir",
		WriteTo:  "veth_131_host",
		ReadFrom: "veth_131_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "SCMPTracerouteIngressConsDir"),
	}
}

// SCMPTracerouteEgress tests an SCMP traceroute request with alert on the
// egress interface.
func SCMPTracerouteEgress(artifactsDir string, mac hash.Hash) runner.Case {
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
				CurrHF: 1,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				ConsDir:   false,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 411, ConsEgress: 0},
			{ConsIngress: 131, ConsEgress: 141, IngressRouterAlert: true},
			{ConsIngress: 0, ConsEgress: 311},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4SCMP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:4"),
		DstIA:        addr.MustParseIA("1-ff00:0:3"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("172.16.4.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.2.1")); err != nil {
		panic(err)
	}

	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPTraceroute{
		Identifier: 567,
		Sequence:   129,
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
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

	sp.HopFields[1].IngressRouterAlert = false
	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}
	scionL.NextHdr = slayers.L4SCMP
	scmpH = &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP = &slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         scionL.SrcIA,
		Interface:  131,
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "SCMPTracerouteEgress",
		WriteTo:  "veth_141_host",
		ReadFrom: "veth_141_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "SCMPTracerouteEgress"),
	}
}

// SCMPTracerouteEgressConsDir tests an SCMP traceroute request with alert on the
// egress interface.
func SCMPTracerouteEgressConsDir(artifactsDir string, mac hash.Hash) runner.Case {
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
			{ConsIngress: 131, ConsEgress: 141, EgressRouterAlert: true},
			{ConsIngress: 411, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4SCMP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:3"),
		DstIA:        addr.MustParseIA("1-ff00:0:4"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("172.16.3.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.4.1")); err != nil {
		panic(err)
	}

	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPTraceroute{
		Identifier: 568,
		Sequence:   130,
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
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
	scionL.SrcIA = addr.MustParseIA("1-ff00:0:1")
	if err := scionL.SetDstAddr(srcA); err != nil {
		panic(err)
	}
	intlA := addr.MustParseHost("192.168.0.11")
	if err := scionL.SetSrcAddr(intlA); err != nil {
		panic(err)
	}

	sp.HopFields[1].EgressRouterAlert = false
	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}
	scionL.NextHdr = slayers.L4SCMP
	scmpH = &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP = &slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         scionL.SrcIA,
		Interface:  141,
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "SCMPTracerouteEgressConsDir",
		WriteTo:  "veth_131_host",
		ReadFrom: "veth_131_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "SCMPTracerouteEgressConsDir"),
	}
}

// SCMPTracerouteEgressAfterXover tests an SCMP traceroute request with alert on the
// egress interface after Xover and the packet was received on the internal interface..
func SCMPTracerouteEgressAfterXover(artifactsDir string, mac hash.Hash) runner.Case {

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
				CurrHF:  2,
				CurrINF: 1,
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
			// down seg
			{
				SegID:     0x222,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 811, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 181},
			{ConsIngress: 0, ConsEgress: 141, EgressRouterAlert: true},
			{ConsIngress: 411, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
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

	srcA := addr.MustParseHost("172.16.8.1")
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	dstA := addr.MustParseHost("172.16.4.1")
	if err := scionL.SetDstAddr(dstA); err != nil {
		panic(err)
	}

	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
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

	// Prepare want packet
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x01}
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

	sp.HopFields[2].EgressRouterAlert = false
	p, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	sp = p.(*scion.Decoded)
	if err := sp.IncPath(); err != nil {
		panic(err)
	}

	scionL.NextHdr = slayers.L4SCMP
	scmpH = &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP = &slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         scionL.SrcIA,
		Interface:  141,
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "SCMPTracerouteEgressAfterXover",
		WriteTo:  "veth_int_host",
		ReadFrom: "veth_int_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "SCMPTracerouteEgressAfterXover"),
	}
}

// SCMPTracerouteInternal tests a traceroute request from the AS itself.
func SCMPTracerouteInternal(artifactsDir string, mac hash.Hash) runner.Case {
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
		SrcIP:    net.IP{192, 168, 0, 51},
		DstIP:    net.IP{192, 168, 0, 11},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(30041),
		DstPort: layers.UDPPort(30001),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 0,
				SegLen: [3]uint8{2, 0, 0},
			},
			NumINF:  1,
			NumHops: 2,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				ConsDir:   true,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 141, EgressRouterAlert: true},
			{ConsIngress: 411, ConsEgress: 0},
		},
	}
	sp.HopFields[0].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[0], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4SCMP,
		PathType:     scion.PathType,
		SrcIA:        addr.MustParseIA("1-ff00:0:1"),
		DstIA:        addr.MustParseIA("1-ff00:0:4"),
		Path:         sp,
	}
	srcA := addr.MustParseHost("192.168.0.51")
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.MustParseHost("174.16.4.1")); err != nil {
		panic(err)
	}

	scmpH := &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPTraceroute{
		Identifier: 568,
		Sequence:   131,
	}

	// Prepare input packet
	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

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

	sp.HopFields[0].EgressRouterAlert = false
	_, err := sp.Reverse()
	if err != nil {
		panic(err)
	}
	scionL.NextHdr = slayers.L4SCMP
	scmpH = &slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP = &slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         scionL.SrcIA,
		Interface:  141,
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scmpH, scmpP,
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "SCMPTracerouteInternal",
		WriteTo:  "veth_int_host",
		ReadFrom: "veth_int_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "SCMPTracerouteInternal"),
	}
}
