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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/tools/braccept/runner"
)

// SVC tests resolution of SVC addresses.
func SVC(artifactsDir string, mac hash.Hash, svcResolverPort int) runner.Case {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef},
		DstMAC:       net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x14},
		EthernetType: layers.EthernetTypeIPv4,
	}
	// IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 14, 3},
		DstIP:    net.IP{192, 168, 14, 2},
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	// 	UDP: Src=40000 Dst=50000
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(40000),
		DstPort: layers.UDPPort(50000),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)
	// SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
	// 		ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:1 Dst=SVC_CS
	// 		IF_1: ISD=1 Hops=2
	// 			HF_1: ConsIngress=411 ConsEgress=0
	// 			HF_2: ConsIngress=0   ConsEgress=141
	// UDP_1: Src=40111 Dst=40222
	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{2, 0, 0},
			},
			NumINF:  1,
			NumHops: 2,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, Timestamp: util.TimeToSecs(time.Now())},
		},
		HopFields: []path.HopField{
			{ConsIngress: 411, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 141},
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
		SrcIA:        xtest.MustParseIA("1-ff00:0:4"),
		DstIA:        xtest.MustParseIA("1-ff00:0:1"),
		Path:         sp,
	}
	if err := scionL.SetSrcAddr(addr.MustParseHost("172.16.4.1")); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(addr.HostSVC(addr.SvcCS)); err != nil {
		panic(err)
	}
	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 2345
	scionudp.DstPort = uint16(svcResolverPort)
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
	// 	Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
	ethernet.SrcMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0x00, 0x1}
	ethernet.DstMAC = net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, 0xbe, 0xef}
	// IP4: Src=192.168.0.11 Dst=192.168.0.71 Checksum=0
	ip.SrcIP = net.IP{192, 168, 0, 11}
	// CS address from the topology file.
	ip.DstIP = net.IP{192, 168, 0, 71}
	udp.SrcPort, udp.DstPort = 30001, layers.UDPPort(svcResolverPort)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)

	if err := gopacket.SerializeLayers(want, options,
		ethernet, ip, udp, scionL, scionudp, gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}

	return runner.Case{
		Name:     "SVC",
		WriteTo:  "veth_141_host",
		ReadFrom: "veth_int_host",
		Input:    input.Bytes(),
		Want:     want.Bytes(),
		StoreDir: filepath.Join(artifactsDir, "SVC"),
	}
}
