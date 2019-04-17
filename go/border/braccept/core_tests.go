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

func core_to_internal_host() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:12 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:1 Dst=192.168.0.51
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=211
				HF_2: ConsIngress=121 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_121")
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

	return ExpectedPackets("core to internal/host", defaultTimeout, pkt1)
}

func internal_host_to_core() int {
	// XXX should we check both segments have Peer flag set? currently not required
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.51 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.51 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=121 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=211
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:12 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.12.2 Dst=192.168.12.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=6
	`)
	pkt1.SetDev("veth_121")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("internal/host to core", defaultTimeout, pkt1)
}

func xover_core_to_internal_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:12 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:8 Dst=172.16.8.1
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=211
				HF_2: ConsIngress=121 ConsEgress=0   Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=181 Flags=Xover
				HF_4: ConsIngress=811 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_121")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")
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

	return ExpectedPackets("xover core to internal/child", defaultTimeout, pkt1)
}

func xover_internal_child_to_core() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.13 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30003 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=7 CurrHopF=8 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:8 Src=172.16.8.1 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=811 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=181 Flags=Xover
			IF_2: ISD=1 Hops=2
				HF_3: ConsIngress=121 ConsEgress=0   Flags=Xover
				HF_4: ConsIngress=0   ConsEgress=211
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "HF_4")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:12 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.12.2 Dst=192.168.12.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=9
	`)
	pkt1.SetDev("veth_121")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("xover internal/child to core", defaultTimeout, pkt1)
}
