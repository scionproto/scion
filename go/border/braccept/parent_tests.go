// Copyright 2018 ETH Zurich
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
	"fmt"
)

func parent_to_internal_host() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:1 Dst=192.168.0.51
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=131 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_131")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.51 Checksum=0
		UDP: Src=30001 Dst=30041
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("parent to internal/host", defaultTimeout, pkt1)
}

func internal_host_to_parent() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.51 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.51 DstIA=1-ff00:0:3 Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=131 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.13.2 Dst=192.168.13.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=6
	`)
	pkt1.SetDev("veth_131")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("internal/host to parent", defaultTimeout, pkt1)
}

func parent_to_internal_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:8 Dst=172.16.8.1
			IF_1: ISD=1 Hops=3 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=131 ConsEgress=181
				HF_3: ConsIngress=811 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_131")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.13 Checksum=0
		UDP: Src=30001 Dst=30003
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("parent to internal/child", defaultTimeout, pkt1)
}

func internal_child_to_parent() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.13 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30003 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:8 Src=172.16.8.1 DstIA=1-ff00:0:3 Dst=172.16.3.1
			IF_1: ISD=1 Hops=3
				HF_1: ConsIngress=811 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=181
				HF_3: ConsIngress=0   ConsEgress=311
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_3")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.13.2 Dst=192.168.13.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=7
	`)
	pkt1.SetDev("veth_131")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("internal/child to parent", defaultTimeout, pkt1)
}

func ohp_parent_to_internal_bs() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:1 Dst=BS
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0 ConsEgress=311
				HF_2: ConsIngress=0 ConsEgress=0 Mac=000000
		HBH: NextHdr=HBH Type=OHP
			HBH.OHP:
	`)
	// XXX HBH and None are the same NextHdr value
	pkt0.SetDev("veth_131")
	pkt0.SetChecksum("UDP", "IP4")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.71 Checksum=0
		UDP: Src=30001 Dst=30041
		SCION:
			HF_2: ConsIngress=131 ConsEgress=0 ExpTime=63
	`)
	// XXX Go BR sets ExpTime to default, which is currently 63
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("one-hop-path parent to internal/bs", defaultTimeout, pkt1)
}

func ohp_udp_parent_to_internal_bs() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:1 Dst=BS
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0 ConsEgress=311
				HF_2: ConsIngress=0 ConsEgress=0 Mac=000000
		HBH: NextHdr=UDP Type=OHP
			HBH.OHP:
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_131")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.71 Checksum=0
		UDP: Src=30001 Dst=30041
		SCION:
			HF_2: ConsIngress=131 ConsEgress=0 ExpTime=63
	`)
	// XXX Go BR sets ExpTime to default, which is currently 63
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("one-hop-path udp parent to internal/bs", defaultTimeout, pkt1)
}

func ohp_udp_internal_bs_to_parent() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.51 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.71 DstIA=1-ff00:0:3 Dst=BS
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=131 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=0 Mac=000000
		HBH: NextHdr=HBH Type=OHP
			HBH.OHP:
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.13.2 Dst=192.168.13.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=6
	`)
	pkt1.SetDev("veth_131")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("one-hop-path up segment internal/bs to parent", defaultTimeout, pkt1)
}

func ohp_internal_bs_to_parent() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.51 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.71 DstIA=1-ff00:0:3 Dst=BS
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0 ConsEgress=131
				HF_2: ConsIngress=0 ConsEgress=0 Mac=000000
		HBH: NextHdr=HBH Type=OHP
			HBH.OHP:
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.13.2 Dst=192.168.13.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=6
	`)
	pkt1.SetDev("veth_131")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("one-hop-path internal/bs to parent", defaultTimeout, pkt1)
}

func parent_scmp_routing_bad_host() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:1 Dst=0009
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=131 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_131")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.13.2 Dst=192.168.13.3 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=50000 Dst=40000 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:3 Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=131 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=ROUTING Type=BAD_HOST Checksum=0
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_131")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	SendPackets(pkt0)

	return ExpectedPackets("parent scmp routing bad host", defaultTimeout, pkt1)
}
