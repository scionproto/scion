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

import "fmt"

func testsBrCoreA() int {
	var failures int

	pkt0 := AllocatePacket()
	pkt0.SetDev("ifid_local")
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30041 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.101 DstIA=1-ff00:0:1 Dst=BS_M
		UDP_1: Src=20001 Dst=0
		IFStateReq:
	`)
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")

	IgnoredPackets(pkt0)

	failures += core_if_core_local()
	failures += core_if_local_core()
	failures += core_if_xover_core_child()
	failures += core_if_xover_child_core()
	failures += core_if_revocation_to_local_isd()

	ClearIgnoredPackets()

	return failures
}

func core_if_core_local() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:1 Dst=192.168.0.51
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=211
				HF_2: ConsIngress=121 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("ifid_121")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.51 Checksum=0
		UDP: Src=30001 Dst=30041
	`)
	pkt1.SetDev("ifid_local")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("Core IF - core/local", defaultTimeout, pkt1)
}

func core_if_local_core() int {
	// XXX should we check both segments have Peer flag set? currently not required
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.0.51 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.51 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=121 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=211
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("ifid_local")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.12.2 Dst=192.168.12.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=6
	`)
	pkt1.SetDev("ifid_121")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("Core IF - local/core", defaultTimeout, pkt1)
}

func core_if_xover_core_child() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=211
				HF_2: ConsIngress=121 ConsEgress=0   Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=141   Flags=Xover
				HF_4: ConsIngress=411 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("ifid_121")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.12 Checksum=0
		UDP: Src=30001 Dst=30002
		SCION: CurrInfoF=7 CurrHopF=8
	`)
	pkt1.SetDev("ifid_local")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("Core IF - Xover core/child", defaultTimeout, pkt1)
}

func core_if_xover_child_core() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.0.13 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30003 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=7 CurrHopF=8 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:5 Src=172.16.5.1 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=141 Flags=Xover
			IF_2: ISD=1 Hops=2
				HF_3: ConsIngress=121 ConsEgress=0   Flags=Xover
				HF_4: ConsIngress=0   ConsEgress=211
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("ifid_local")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "HF_4")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.12.2 Dst=192.168.12.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrHopF=9
	`)
	pkt1.SetDev("ifid_121")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("Core IF - Xover child/core", defaultTimeout, pkt1)
}

func core_if_revocation_to_local_isd() int {
	pktError := AllocatePacket()
	pktError.ParsePacket(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=0.0.0.0 Dst=0.0.0.0 NextHdr=UDP Checksum=0
		UDP: Dst=30041 Checksum=0
		SCION: NextHdr=UDP CurrInfoF=7 CurrHopF=8 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:9 Dst=172.16.9.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=141 Flags=Xover
			IF_2: ISD=1 Hops=2
				HF_3: ConsIngress=121 ConsEgress=0   Flags=Xover
				HF_4: ConsIngress=0   ConsEgress=211
		UDP_1: Src=40111 Dst=40222 Checksum=0
	`)

	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=211
				HF_2: ConsIngress=121 ConsEgress=0   Flags=Xover
			IF_2: ISD=1 Hops=2 Flags=ConsDir
				HF_3: ConsIngress=0   ConsEgress=141 Flags=Xover
				HF_4: ConsIngress=411 ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=REVOKED_IF Timestamp=now
			InfoRevocation: InfoF=4 HopF=6 IfID=999 Ingress=false
				SignedRevInfo: IfID=999 IA=1-ff00:0:9 Link=child TS=now TTL=10
			QUOTED: RawPkt=%s
	`, pktError.Serialize()))
	pkt0.SetDev("ifid_121")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("SCMP", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.12 Checksum=0
		UDP: Src=30001 Dst=30002
		SCION: CurrInfoF=7 CurrHopF=8
	`)
	pkt1.SetDev("ifid_local")
	pkt1.SetChecksum("UDP", "IP4")

	pkt2 := AllocatePacket()
	pkt2.ParsePacket(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.51 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30041 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.101 DstIA=1-ff00:0:1 Dst=PS
		UDP_1: Src=20001 Dst=0
		SignedRevInfo: IfID=999 IA=1-ff00:0:9 Link=child TS=now TTL=10
	`)
	pkt2.SetDev("ifid_local")
	pkt2.SetChecksum("UDP", "IP4")
	pkt2.SetChecksum("UDP_1", "SCION")

	pkt3 := pkt2.CloneAndUpdate(`
		IP4: Dst=192.168.0.61
		SCION:
			ADDR: Dst=BS
	`)
	pkt3.SetDev("ifid_local")
	pkt3.SetChecksum("UDP", "IP4")
	pkt3.SetChecksum("UDP_1", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("Core IF - Revocation to local ISD, fork to PS and BS",
		defaultTimeout, pkt1, pkt2, pkt3)
}
