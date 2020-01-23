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

	"github.com/scionproto/scion/go/border/braccept/shared"
)

func revocation_core_to_local_isd() int {
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
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:12 EthernetType=IPv4
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
	pkt0.SetDev("veth_121")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("SCMP", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")
	pkt0.GenerateMac("SCION", "IF_2", "HF_3", "")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=7 CurrHopF=9
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	pkt2 := AllocatePacket()
	pkt2.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.71 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30041 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.101 DstIA=1-ff00:0:1 Dst=PS
		UDP_1: Src=20001 Dst=0
		SignedRevInfo: IfID=999 IA=1-ff00:0:9 Link=child TS=now TTL=10
	`)
	pkt2.SetDev("veth_int")
	pkt2.SetChecksum("UDP", "IP4")
	pkt2.SetChecksum("UDP_1", "SCION")

	pkt3 := pkt2.CloneAndUpdate(`
		IP4: Dst=192.168.0.71
		SCION:
			ADDR: Dst=BS
	`)
	pkt3.SetDev("veth_int")
	pkt3.SetChecksum("UDP", "IP4")
	pkt3.SetChecksum("UDP_1", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("Revocation from core to local ISD, fork to PS and BS",
		defaultTimeout, pkt1, pkt2, pkt3)
}

func revocation_child_to_internal_host() int {
	pktError := AllocatePacket()
	pktError.ParsePacket(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=0.0.0.0 Dst=0.0.0.0 NextHdr=UDP Checksum=0
		UDP: Dst=30041 Checksum=0
		SCION: NextHdr=UDP CurrInfoF=7 CurrHopF=8 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.71 DstIA=1-ff00:0:a Dst=172.16.10.1
			IF_1: ISD=1 Hops=4 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=131 ConsEgress=141
				HF_3: ConsIngress=411 ConsEgress=491
				HF_4: ConsIngress=941 ConsEgress=0
		UDP_1: Src=40111 Dst=40222 Checksum=0
	`)

	// Link between 491 <-> 941 is down, so ff00:0:4 has IFID 491 revoked
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:14 EthernetType=IPv4
		IP4: Src=192.168.14.3 Dst=192.168.14.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=7 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:1 Dst=192.168.0.71
			IF_1: ISD=1 Hops=4
				HF_1: ConsIngress=941 ConsEgress=0
				HF_2: ConsIngress=411 ConsEgress=491
				HF_3: ConsIngress=131 ConsEgress=141
				HF_4: ConsIngress=0   ConsEgress=311
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=REVOKED_IF Timestamp=now
			InfoRevocation: InfoF=4 HopF=6 IfID=491 Ingress=false
				SignedRevInfo: IfID=491 IA=1-ff00:0:4 Link=child TS=now TTL=10
			QUOTED: RawPkt=%s
	`, pktError.Serialize()))
	pkt0.SetDev("veth_141")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("SCMP", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_3", "HF_4")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.71 Checksum=0
		UDP: Src=30001 Dst=30041
	`)
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")

	pkt2 := AllocatePacket()
	pkt2.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.71 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30041 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.101 DstIA=1-ff00:0:1 Dst=PS
		UDP_1: Src=20001 Dst=0
		SignedRevInfo: IfID=491 IA=1-ff00:0:4 Link=child TS=now TTL=10
	`)
	pkt2.SetDev("veth_int")
	pkt2.SetChecksum("UDP", "IP4")
	pkt2.SetChecksum("UDP_1", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("Revocation child to internal host, fork to PS",
		defaultTimeout, pkt1, pkt2)
}

func revocation_parent_to_child() int {
	pktError := AllocatePacket()
	pktError.ParsePacket(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=0.0.0.0 Dst=0.0.0.0 NextHdr=UDP Checksum=0
		UDP: Dst=30041 Checksum=0
		SCION: NextHdr=UDP CurrInfoF=7 CurrHopF=8 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:4 Src=172.16.4.1 DstIA=1-ff00:0:a Dst=172.16.10.1
			IF_1: ISD=1 Hops=4
				HF_1: ConsIngress=411 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=141
				HF_3: ConsIngress=999 ConsEgress=311
				HF_4: ConsIngress=0   ConsEgress=1
		UDP_1: Src=40111 Dst=40222 Checksum=0
	`)

	// Link between 999 <-> 1 is down, so ff00:0:3 has IFID 999 revoked
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:13 EthernetType=IPv4
		IP4: Src=192.168.13.3 Dst=192.168.13.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=7 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:3 Src=172.16.3.1 DstIA=1-ff00:0:4 Dst=172.16.4.1
			IF_1: ISD=1 Hops=4 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=1
				HF_2: ConsIngress=999 ConsEgress=311
				HF_3: ConsIngress=131 ConsEgress=141
				HF_4: ConsIngress=411 ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=REVOKED_IF Timestamp=now
			InfoRevocation: InfoF=4 HopF=6 IfID=999 Ingress=false
				SignedRevInfo: IfID=999 IA=1-ff00:0:3 Link=child TS=now TTL=10
			QUOTED: RawPkt=%s
	`, pktError.Serialize()))
	pkt0.SetDev("veth_131")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("SCMP", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_3", "HF_2")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:14 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.14.2 Dst=192.168.14.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=4 CurrHopF=8
	`)
	pkt1.SetDev("veth_141")
	pkt1.SetChecksum("UDP", "IP4")

	pkt2 := AllocatePacket()
	pkt2.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.71 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30041 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.101 DstIA=1-ff00:0:1 Dst=PS
		UDP_1: Src=20001 Dst=0
		SignedRevInfo: IfID=999 IA=1-ff00:0:3 Link=child TS=now TTL=10
	`)
	pkt2.SetDev("veth_int")
	pkt2.SetChecksum("UDP", "IP4")
	pkt2.SetChecksum("UDP_1", "SCION")

	pkt3 := pkt2.CloneAndUpdate(`
		IP4: Dst=192.168.0.71
		SCION:
			ADDR: Dst=BS
	`)
	pkt3.SetDev("veth_int")
	pkt3.SetChecksum("UDP", "IP4")
	pkt3.SetChecksum("UDP_1", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("Revocation from parent to child, fork to PS and BS",
		defaultTimeout, pkt1, pkt2, pkt3)
}

func revocation_owned_peer() int {

	shared.UpdateNow()

	ifStateDown := AllocatePacket()
	ifStateDown.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=1-ff00:0:1 Dst=192.168.0.101
		UDP_1: Src=20006 Dst=20001
		IFStateInfo: IfID=121 Active=false
			SignedRevInfo: IfID=121 IA=1-ff00:0:1 Link=peer TS=now TTL=10
	`)
	ifStateDown.SetDev("veth_int")
	ifStateDown.SetChecksum("UDP", "IP4")
	ifStateDown.SetChecksum("UDP_1", "SCION")

	SendPackets(ifStateDown)
	Sleep("250ms")

	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.71 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.71 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=3 Flags=Peer,Shortcut
				HF_1: ConsIngress=131 ConsEgress=0   Flags=Xover
				HF_2: ConsIngress=121 ConsEgress=0   Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
			IF_2: ISD=2 Hops=3 Flags=ConsDir,Peer,Shortcut
				HF_4: ConsIngress=0   ConsEgress=321 Flags=VerifyOnly
				HF_5: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_6: ConsIngress=231 ConsEgress=0   Flags=Xover
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_3")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	// SCMP revocation reply (reversed SCION header) from the BR to the source of the packet.
	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.71 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=30041 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=8 CurrHopF=10 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.71
			IF_1: ISD=2 Hops=3 Flags=Peer,Shortcut
				HF_1: ConsIngress=231 ConsEgress=0   Flags=Xover
				HF_2: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=321 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir,Peer,Shortcut
				HF_4: ConsIngress=0   ConsEgress=311 Flags=VerifyOnly
				HF_5: ConsIngress=121 ConsEgress=0   Flags=Xover
				HF_6: ConsIngress=131 ConsEgress=0   Flags=Xover
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=REVOKED_IF Checksum=0
			InfoRevocation: InfoF=4 HopF=6 IfID=121 Ingress=false
				SignedRevInfo: IfID=121 IA=1-ff00:0:1 Link=peer TS=now TTL=10
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_2", "HF_6", "HF_4")
	pkt1.GenerateMac("SCION", "IF_2", "HF_5", "HF_6")

	SendPackets(pkt0)

	ret := ExpectedPackets("revoked peer interface", defaultTimeout, pkt1)

	ifStateUp := ifStateDown.CloneAndUpdate(`
		IFStateInfo: Active=true
	`)
	SendPackets(ifStateUp)
	Sleep("250ms")

	return ret
}

// TODO WIP
// forward revocation:
//   child to parent
//   child to peer
//   child to core
//   core to core (revocation destination is not BR ISD)
// forward revocation and fork to PS:
//   child to parent
//   child to parent
//   child to parent
//   parent to internal host
// forward revocation and fork to PS and BS:
//   parent to internal child
// revocation reply:
//   interface not owned
//   owned child interface
//   owned core interface
//   overlapping revocations

func revocation_owned_parent() int {

	shared.UpdateNow()

	ifStateDown := AllocatePacket()
	ifStateDown.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=1-ff00:0:1 Dst=192.168.0.101
		UDP_1: Src=20006 Dst=20001
		IFStateInfo: IfID=131 Active=false
			SignedRevInfo: IfID=131 IA=1-ff00:0:1 Link=parent TS=now TTL=10
	`)
	ifStateDown.SetDev("veth_int")
	ifStateDown.SetChecksum("UDP", "IP4")
	ifStateDown.SetChecksum("UDP_1", "SCION")

	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.71 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.71 DstIA=1-ff00:0:3 Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=131 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	// SCMP revocation reply (reversed SCION header) from the BR to the source of the packet.
	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.71 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=30041 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.71
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=131 ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=REVOKED_IF Checksum=0
			InfoRevocation: InfoF=4 HopF=5 IfID=131 Ingress=false
				SignedRevInfo: IfID=131 IA=1-ff00:0:1 Link=parent TS=now TTL=10
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	// Send/Expect packets
	SendPackets(ifStateDown)
	Sleep("250ms")

	SendPackets(pkt0)

	ret := ExpectedPackets("revoked parent interface", defaultTimeout, pkt1)

	ifStateUp := ifStateDown.CloneAndUpdate(`
		IFStateInfo: Active=true
	`)
	SendPackets(ifStateUp)
	Sleep("250ms")

	return ret
}

func revocation_not_owned_child_link() int {

	shared.UpdateNow()

	ifStateDown := AllocatePacket()
	ifStateDown.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=1-ff00:0:1 Dst=192.168.0.101
		UDP_1: Src=20006 Dst=20001
		IFStateInfo: IfID=181 Active=false
			SignedRevInfo: IfID=181 IA=1-ff00:0:1 Link=child TS=now TTL=10
	`)
	ifStateDown.SetDev("veth_int")
	ifStateDown.SetChecksum("UDP", "IP4")
	ifStateDown.SetChecksum("UDP_1", "SCION")

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

	// SCMP revocation reply (reversed SCION header) from the BR to the source of the packet.
	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:13 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.13.2 Dst=192.168.13.3 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=50000 Dst=40000 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=7 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:3 Dst=172.16.3.1
			IF_1: ISD=1 Hops=3
				HF_1: ConsIngress=811 ConsEgress=0
				HF_2: ConsIngress=131 ConsEgress=181
				HF_3: ConsIngress=0   ConsEgress=311
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=REVOKED_IF Checksum=0
			InfoRevocation: InfoF=4 HopF=6 IfID=181 Ingress=true
				SignedRevInfo: IfID=181 IA=1-ff00:0:1 Link=child TS=now TTL=10
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_131")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_3")

	// Send/Expect packets
	SendPackets(ifStateDown)
	Sleep("250ms")

	SendPackets(pkt0)

	ret := ExpectedPackets("revoked child (not owned) interface", "500ms", pkt1)

	ifStateUp := ifStateDown.CloneAndUpdate(`
		IFStateInfo: Active=true
	`)
	SendPackets(ifStateUp)
	Sleep("250ms")

	return ret
}
