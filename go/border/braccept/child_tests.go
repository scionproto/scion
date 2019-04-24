// Copyright 2019 ETH Zurich
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

func child_to_internal_host() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:1 Dst=192.168.0.51
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=141
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.51 Checksum=0
		UDP: Src=30001 Dst=30041
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("child to internal/host", defaultTimeout, pkt1)
}

func internal_host_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.51 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.51 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=141
				HF_2: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=6
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("internal/host to child", defaultTimeout, pkt1)
}

//
// Xover tests: these are the test for core BRs with segment change
//
func xover_child_to_internal_core() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:7 Dst=172.16.7.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=141 Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=171 Flags=Xover
				HF_4: ConsIngress=711 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.12 Checksum=0
		UDP: Src=30001 Dst=30002
		SCION: CurrInfoF=7 CurrHopF=8
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("xover child to internal/core", defaultTimeout, pkt1)
}

func xover_internal_core_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.12 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30002 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=7 CurrHopF=8 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:7 Src=172.16.7.1 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=711 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=171 Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=141 Flags=Xover
				HF_4: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=9
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("xover internal/core to child", defaultTimeout, pkt1)
}

func xover_child_to_internal_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:8 Dst=172.16.8.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=141 Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=181 Flags=Xover
				HF_4: ConsIngress=811 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.13 Checksum=0
		UDP: Src=30001 Dst=30003
		SCION: CurrInfoF=7 CurrHopF=8
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("xover child to internal/child", defaultTimeout, pkt1)
}

func xover_internal_child_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.13 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30003 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=7 CurrHopF=8 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:8 Src=172.16.8.1 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=811 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=181 Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=141 Flags=Xover
				HF_4: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=9
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("xover internal/child to child", defaultTimeout, pkt1)
}

//
// Shortcut tests: these are the tests for non-core BRs
//
func child_to_internal_parent() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=174.16.4.1 DstIA=1-ff00:0:9 Dst=172.16.9.1
			IF_1: ISD=1 Hops=3
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=191 ConsEgress=141
				HF_3: ConsIngress=0   ConsEgress=911 Flags=VerifyOnly
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_3")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.14 Checksum=0
		UDP: Src=30001 Dst=30004
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("child to internal/parent", defaultTimeout, pkt1)
}

func internal_parent_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.14 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30004 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:9 Src=174.16.9.1 DstIA=1-ff00:0:4 Dst=174.16.4.1
			IF_1: ISD=1 Hops=3 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=911 Flags=VerifyOnly
				HF_2: ConsIngress=191 ConsEgress=141
				HF_3: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
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

	return ExpectedPackets("internal/parent to child", defaultTimeout, pkt1)
}

func shortcut_child_to_internal_peer() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:7 Dst=172.16.7.1
			IF_1: ISD=1 Hops=4 Flags=Shortcut,Peer
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=191 ConsEgress=141 Flags=Xover
				HF_3: ConsIngress=171 ConsEgress=141 Flags=Xover
				HF_4: ConsIngress=0   ConsEgress=912 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir
				HF_5: ConsIngress=0   ConsEgress=921 Flags=VerifyOnly
				HF_6: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_7: ConsIngress=291 ConsEgress=0   Flags=Xover
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_3", "HF_2")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.12 Checksum=0
		UDP: Src=30001 Dst=30002
		SCION: CurrHopF=7
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("shortcut child to internal/peer", defaultTimeout, pkt1)
}

func shortcut_internal_peer_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.12 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30002 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=8 CurrHopF=11 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:7 Src=172.16.7.1 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=3 Flags=Peer
				HF_1: ConsIngress=291 ConsEgress=0   Flags=Xover
				HF_2: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=921
			IF_2: ISD=1 Hops=4 Flags=ConsDir,Shortcut,Peer
				HF_4: ConsIngress=0   ConsEgress=911
				HF_5: ConsIngress=171 ConsEgress=141 Flags=Xover
				HF_6: ConsIngress=191 ConsEgress=141 Flags=Xover
				HF_7: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
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

	return ExpectedPackets("shortcut internal/peer to child", defaultTimeout, pkt1)
}

func shortcut_child_to_internal_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:8 Dst=172.16.8.1
			IF_1: ISD=1 Hops=3 Flags=Shortcut
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=141 Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir,Shortcut
				HF_4: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
				HF_5: ConsIngress=131 ConsEgress=181 Flags=Xover
				HF_6: ConsIngress=811 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_3")
	pkt0.GenerateMac("SCION", "IF_2", "HF_5", "HF_4")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.13 Checksum=0
		UDP: Src=30001 Dst=30003
		SCION: CurrInfoF=8 CurrHopF=10
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("shortcut child to internal/child", defaultTimeout, pkt1)
}

func shortcut_internal_child_to_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.13 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30003 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=8 CurrHopF=10 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:8 Src=172.16.8.1 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=3 Flags=Shortcut
				HF_1: ConsIngress=811 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=181 Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir,Shortcut
				HF_4: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
				HF_5: ConsIngress=131 ConsEgress=141 Flags=Xover
				HF_6: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_3")
	pkt0.GenerateMac("SCION", "IF_2", "HF_5", "HF_4")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=11
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("shortcut internal/child to child", defaultTimeout, pkt1)
}
