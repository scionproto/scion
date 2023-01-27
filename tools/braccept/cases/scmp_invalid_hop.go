// Copyright 2022 SCION Association
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

// SCMPInvalidHopParentToParent tests a packet that attempts a hop from a parent to
// a parent interface, with a valid hopfield MAC. This can only occur if the
// hop key has been compromised.
func SCMPInvalidHopParentToParent(artifactsDir string, mac hash.Hash) runner.Case {
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
				SegLen:  [3]uint8{3, 0, 0},
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
			{ConsIngress: 131, ConsEgress: 191},
			{ConsIngress: 911, ConsEgress: 0},
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
		DstIA:        xtest.MustParseIA("1-ff00:0:9"),
		Path:         sp,
	}
	srcA := &net.IPAddr{IP: net.ParseIP("172.16.5.1")}
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(&net.IPAddr{IP: net.ParseIP("174.16.4.1")}); err != nil {
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

	// Pointer to current hop field
	pointer := slayers.CmnHdrLen + scionL.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*sp.NumINF + path.HopLen*int(sp.PathMeta.CurrHF)

	// Prepare quoted packet that is part of the SCMP error message.
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
		TypeCode: slayers.CreateSCMPTypeCode(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidPath,
		),
	}

	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPParameterProblem{
		Pointer: uint16(pointer),
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP, gopacket.Payload(quote),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPInvalidHopParentToParent",
		WriteTo:         "veth_131_host",
		ReadFrom:        "veth_131_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPInvalidHopParentToParent"),
		NormalizePacket: scmpNormalizePacket,
	}
}

// SCMPInvalidHopChildToChild tests a packet that attempts a hop from a child to
// a child interface, with a valid hopfield MAC. This can only occur if the
// hop key has been compromised.
func SCMPInvalidHopChildToChild(artifactsDir string, mac hash.Hash) runner.Case {
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
				SegLen:  [3]uint8{3, 0, 0},
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
			{ConsIngress: 0, ConsEgress: 411},
			{ConsIngress: 141, ConsEgress: 151},
			{ConsIngress: 511, ConsEgress: 0},
		},
	}
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        xtest.MustParseIA("1-ff00:0:4"),
		DstIA:        xtest.MustParseIA("1-ff00:0:5"),
		Path:         sp,
	}
	srcA := &net.IPAddr{IP: net.ParseIP("172.16.5.1")}
	if err := scionL.SetSrcAddr(srcA); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(&net.IPAddr{IP: net.ParseIP("174.16.4.1")}); err != nil {
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

	// Pointer to current hop field
	pointer := slayers.CmnHdrLen + scionL.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*sp.NumINF + path.HopLen*int(sp.PathMeta.CurrHF)

	// Prepare quoted packet that is part of the SCMP error message.
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
		TypeCode: slayers.CreateSCMPTypeCode(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidPath,
		),
	}

	scmpH.SetNetworkLayerForChecksum(scionL)
	scmpP := &slayers.SCMPParameterProblem{
		Pointer: uint16(pointer),
	}

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, e2e, scmpH, scmpP, gopacket.Payload(quote),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:            "SCMPInvalidHopChildToChild",
		WriteTo:         "veth_141_host",
		ReadFrom:        "veth_141_host",
		Input:           input.Bytes(),
		Want:            want.Bytes(),
		StoreDir:        filepath.Join(artifactsDir, "SCMPInvalidHopChildToChild"),
		NormalizePacket: scmpNormalizePacket,
	}
}
