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

func core_to_core() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:12 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:3 Dst=172.16.3.1
			IF_1: ISD=1 Hops=3
				HF_1: ConsIngress=211 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=121
				HF_3: ConsIngress=0   ConsEgress=311
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_121")
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

	return ExpectedPackets("core to core", defaultTimeout, pkt1)
}

func xover_core_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:5 Dst=172.16.5.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=311 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=131 Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=151 Flags=Xover
				HF_4: ConsIngress=511 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_131")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:15 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.15.2 Dst=192.168.15.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=7 CurrHopF=9
	`)
	pkt1.SetDev("veth_151")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("xover core to child", defaultTimeout, pkt1)
}

func xover_child_to_core() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:15 EthernetType=IPv4
		IP4: Src=192.168.15.3 Dst=192.168.15.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:5 Src=172.16.5.1 DstIA=1-ff00:0:3 Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=511 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=151 Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=131 Flags=Xover
				HF_4: ConsIngress=311 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_151")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.13.2 Dst=192.168.13.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=7 CurrHopF=9
	`)
	pkt1.SetDev("veth_131")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("xover child to core", defaultTimeout, pkt1)
}

func xover_child_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:15 EthernetType=IPv4
		IP4: Src=192.168.15.3 Dst=192.168.15.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:5 Src=172.16.5.1 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=511 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=151 Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=141 Flags=Xover
				HF_4: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_151")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=7 CurrHopF=9
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("xover child to child", defaultTimeout, pkt1)
}

func child_to_parent() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=174.16.4.1 DstIA=1-ff00:0:3 Dst=172.16.3.1
			IF_1: ISD=1 Hops=3
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=141
				HF_3: ConsIngress=0   ConsEgress=311
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
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

	return ExpectedPackets("child to parent", defaultTimeout, pkt1)
}

func parent_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:3 Src=174.16.3.1 DstIA=1-ff00:0:4 Dst=174.16.4.1
			IF_1: ISD=1 Hops=3 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=131 ConsEgress=141
				HF_3: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_131")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=7
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("parent to child", defaultTimeout, pkt1)
}
func shortcut_child_to_peer() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=4 Flags=Shortcut,Peer
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=141 Flags=Xover
				HF_3: ConsIngress=121 ConsEgress=141 Flags=Xover
				HF_4: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir
				HF_5: ConsIngress=0   ConsEgress=321 Flags=VerifyOnly
				HF_6: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_7: ConsIngress=231 ConsEgress=0   Flags=Xover
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_3", "HF_2")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:12 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.12.2 Dst=192.168.12.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=9 CurrHopF=11
	`)
	pkt1.SetDev("veth_121")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("shortcut child to peer", defaultTimeout, pkt1)
}

func shortcut_peer_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:12 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=8 CurrHopF=10 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=3 Flags=Shortcut,Peer
				HF_1: ConsIngress=231 ConsEgress=0   Flags=Xover
				HF_2: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
			IF_2: ISD=1 Hops=4 Flags=ConsDir,Shortcut,Peer
				HF_4: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
				HF_5: ConsIngress=121 ConsEgress=141 Flags=Xover
				HF_6: ConsIngress=131 ConsEgress=141 Flags=Xover
				HF_7: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_121")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_2", "HF_6", "HF_4")
	pkt0.GenerateMac("SCION", "IF_2", "HF_5", "HF_6")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=12
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("shortcut peer to child", defaultTimeout, pkt1)
}

func shortcut_child_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:5 Dst=172.16.5.1
			IF_1: ISD=1 Hops=3 Flags=Shortcut
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=141 Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir,Shortcut
				HF_4: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
				HF_5: ConsIngress=131 ConsEgress=151 Flags=Xover
				HF_6: ConsIngress=511 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_3")
	pkt0.GenerateMac("SCION", "IF_2", "HF_5", "HF_4")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:15 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.15.2 Dst=192.168.15.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=8 CurrHopF=11
	`)
	pkt1.SetDev("veth_151")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("shortcut child to child", defaultTimeout, pkt1)
}
