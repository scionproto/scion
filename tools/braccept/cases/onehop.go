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
	"encoding/binary"
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
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/tools/braccept/runner"
)

// IncomingOneHop tests one-hop being sent from the remote AS to the local AS.
func IncomingOneHop(artifactsDir string, mac hash.Hash) runner.Case {
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
	ohp := &onehop.Path{
		Info: path.InfoField{
			ConsDir:   true,
			SegID:     0x111,
			Timestamp: util.TimeToSecs(time.Now()),
		},
		FirstHop:  path.HopField{ConsIngress: 0, ConsEgress: 311},
		SecondHop: path.HopField{ConsIngress: 0, ConsEgress: 0},
	}
	ohp.FirstHop.Mac = path.MAC(mac, ohp.Info, ohp.FirstHop, nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     onehop.PathType,
		SrcIA:        xtest.MustParseIA("1-ff00:0:3"),
		DstIA:        xtest.MustParseIA("1-ff00:0:1"),
		Path:         ohp,
	}
	if err := scionL.SetSrcAddr(&net.IPAddr{IP: net.ParseIP("172.16.4.1")}); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(&net.IPAddr{IP: net.ParseIP("192.168.0.71")}); err != nil {
		panic(err)
	}

	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 2345
	scionudp.DstPort = 53
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
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x1}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	ip.SrcIP = net.IP{192, 168, 0, 11}
	ip.DstIP = net.IP{192, 168, 0, 71}
	udp.SrcPort, udp.DstPort = 30001, 30041
	// Second hop in OHP should have been set by BR.
	ohp.SecondHop.ConsIngress = 131
	ohp.SecondHop.Mac = path.MAC(mac, ohp.Info, ohp.SecondHop, nil)

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "IncomingOneHop",
		WriteTo:  "veth_131_host",
		ReadFrom: "veth_int_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "IncomingOneHop"),
	}
}

// OutgoingOneHop tests one-hop being sent from the local AS to the remote AS.
func OutgoingOneHop(artifactsDir string, mac hash.Hash) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 0, 71},
		DstIP:    net.IP{192, 168, 0, 11},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(30041),
		DstPort: layers.UDPPort(30001),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)
	ohp := &onehop.Path{
		Info: path.InfoField{
			ConsDir:   true,
			SegID:     0x111,
			Timestamp: util.TimeToSecs(time.Now()),
		},
		FirstHop: path.HopField{ConsIngress: 0, ConsEgress: 141},
		// Don't set the second hop. It is supposed to be set by the remote BR.
	}
	ohp.FirstHop.Mac = path.MAC(mac, ohp.Info, ohp.FirstHop, nil)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     onehop.PathType,
		SrcIA:        xtest.MustParseIA("1-ff00:0:1"),
		DstIA:        xtest.MustParseIA("1-ff00:0:4"),
		Path:         ohp,
	}
	if err := scionL.SetSrcAddr(&net.IPAddr{IP: net.ParseIP("192.168.0.71")}); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(&net.IPAddr{IP: net.ParseIP("172.16.4.1")}); err != nil {
		panic(err)
	}

	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 2345
	scionudp.DstPort = 53
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
	want := gopacket.NewSerializeBuffer()
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x14}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	ip.SrcIP = net.IP{192, 168, 14, 2}
	ip.DstIP = net.IP{192, 168, 14, 3}
	udp.SrcPort, udp.DstPort = 50000, 40000
	ohp.Info.SegID = ohp.Info.SegID ^ binary.BigEndian.Uint16(ohp.FirstHop.Mac[:2])

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "OutgoingOneHop",
		WriteTo:  "veth_int_host",
		ReadFrom: "veth_141_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "OutgoingOneHop"),
	}
}
