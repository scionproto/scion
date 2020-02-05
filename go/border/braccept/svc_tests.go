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

func svc_anycast_parent_to_internal_host() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:1 Dst=BS
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
		IP4: Src=192.168.0.11 Dst=192.168.0.71 Checksum=0
		UDP: Src=30001 Dst=30041
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("SVC anycast parent to internal/host", defaultTimeout, pkt1)
}

func svc_multicast_parent_to_internal_host() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:1 Dst=SIG_M
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

	pkt2 := pkt1.CloneAndUpdate(`
		IP4: Src=192.168.0.11 Dst=192.168.0.61 Checksum=0
	`)
	pkt2.SetDev("veth_int")
	pkt2.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("SVC multicast parent to internal/host", defaultTimeout, pkt1, pkt2)
}

func svc_multicast_same_host_parent_to_internal_host() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:1 Dst=PS_M
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
		IP4: Src=192.168.0.11 Dst=192.168.0.71 Checksum=0
		UDP: Src=30001 Dst=30041
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("SVC multicast (same host) parent to internal/host",
		defaultTimeout, pkt1)
}
