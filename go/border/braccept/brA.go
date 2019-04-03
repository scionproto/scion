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

func testsBrA() int {
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

	failures += xover_peer_local()
	failures += xover_local_peer()
	failures += xover_peer_child()
	failures += xover_child_peer()
	failures += revocation_owned_peer()

	ClearIgnoredPackets()

	return failures
}

func xover_peer_local() int {
	// Xover peer/local
	pkt0 := AllocatePacket()
	pkt0.SetDev("ifid_121")
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=8 CurrHopF=10 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:1 Dst=192.168.0.51
			IF_1: ISD=1 Hops=3 Flags=Peer
				HF_1: ConsIngress=261 ConsEgress=0   Flags=Xover
				HF_2: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=621
			IF_2: ISD=1 Hops=3 Flags=ConsDir
				HF_4: ConsIngress=0   ConsEgress=611
				HF_5: ConsIngress=121 ConsEgress=0   Flags=Xover
				HF_6: ConsIngress=161 ConsEgress=0   Flags=Xover
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_2", "HF_5", "HF_4")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.51 Checksum=0
		UDP: Src=30001 Dst=30041
	`)
	pkt1.SetDev("ifid_local")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("Xover peer/local", defaultTimeout, pkt1)
}

func xover_local_peer() int {
	// Xover local/peer
	// XXX should we check both segments have Peer flag set? currently not required
	pkt0 := AllocatePacket()
	pkt0.SetDev("ifid_local")
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.0.51 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30041 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.51 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=3 Flags=Peer,Shortcut
				HF_1: ConsIngress=161 ConsEgress=0   Flags=Xover
				HF_2: ConsIngress=121 ConsEgress=0   Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=611 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir
				HF_4: ConsIngress=0   ConsEgress=621 Flags=VerifyOnly
				HF_5: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_6: ConsIngress=261 ConsEgress=0   Flags=Xover
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_3")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.12.2 Dst=192.168.12.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=8 CurrHopF=10
	`)
	pkt1.SetDev("ifid_121")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("Xover local/peer", defaultTimeout, pkt1)
}

func xover_peer_child() int {
	// Xover peer/child
	pkt0 := AllocatePacket()
	pkt0.SetDev("ifid_121")
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.12.3 Dst=192.168.12.2 NextHdr=UDP Flags=DF
		UDP: Src=40000 Dst=50000
		SCION: NextHdr=UDP CurrInfoF=8 CurrHopF=10 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:2 Src=172.16.2.1 DstIA=1-ff00:0:5 Dst=172.16.5.1
			IF_1: ISD=1 Hops=3 Flags=Peer
				HF_1: ConsIngress=261 ConsEgress=0   Flags=Xover
				HF_2: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=621
			IF_2: ISD=1 Hops=4 Flags=ConsDir,Shortcut,Peer
				HF_4: ConsIngress=0   ConsEgress=612
				HF_5: ConsIngress=121 ConsEgress=151 Flags=Xover
				HF_6: ConsIngress=162 ConsEgress=151 Flags=Xover
				HF_7: ConsIngress=511 ConsEgress=0
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_2", "HF_6", "HF_4")
	pkt0.GenerateMac("SCION", "IF_2", "HF_5", "HF_6")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.0.11 Dst=192.168.0.14 Checksum=0
		UDP: Src=30001 Dst=30004
		SCION: CurrHopF=11
	`)
	pkt1.SetDev("ifid_local")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("Xover peer/child", defaultTimeout, pkt1)
}

func xover_child_peer() int {
	// Xover child/peer
	pkt0 := AllocatePacket()
	pkt0.SetDev("ifid_local")
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.0.13 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30003 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=7 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:5 Src=172.16.5.1 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=4 Flags=Shortcut,Peer
				HF_1: ConsIngress=511 ConsEgress=0
				HF_2: ConsIngress=162 ConsEgress=151 Flags=Xover
				HF_3: ConsIngress=121 ConsEgress=151 Flags=Xover
				HF_4: ConsIngress=0   ConsEgress=612 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir
				HF_5: ConsIngress=0   ConsEgress=621 Flags=VerifyOnly
				HF_6: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_7: ConsIngress=261 ConsEgress=0   Flags=Xover
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_3", "HF_2")

	pkt1 := pkt0.CloneAndUpdate(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef
		IP4: Src=192.168.12.2 Dst=192.168.12.3 Checksum=0
		UDP: Src=50000 Dst=40000
		SCION: CurrInfoF=9 CurrHopF=11
	`)
	pkt1.SetDev("ifid_121")
	pkt1.SetChecksum("UDP", "IP4")

	SendPackets(pkt0)

	return ExpectedPackets("Xover child/peer", defaultTimeout, pkt1)
}

func revocation_owned_peer() int {
	ifStateDown := AllocatePacket()
	ifStateDown.SetDev("ifid_local")
	ifStateDown.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=1-ff00:0:1 Dst=192.168.0.101
		UDP_1: Src=20006 Dst=20001
		IFStateInfo: IfID=121 Active=false
			SignedRevInfo: IfID=121 IA=1-ff00:0:1 Link=peer TS=now TTL=10
	`)
	ifStateDown.SetChecksum("UDP", "IP4")
	ifStateDown.SetChecksum("UDP_1", "SCION")

	SendPackets(ifStateDown)
	Sleep("250ms")

	pkt0 := AllocatePacket()
	pkt0.SetDev("ifid_local")
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=00:00:00:00:00:00 EthernetType=IPv4
		IP4: Src=192.168.0.13 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=30003 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=7 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:5 Src=172.16.5.1 DstIA=1-ff00:0:2 Dst=172.16.2.1
			IF_1: ISD=1 Hops=4 Flags=Shortcut,Peer
				HF_1: ConsIngress=511 ConsEgress=0
				HF_2: ConsIngress=162 ConsEgress=151 Flags=Xover
				HF_3: ConsIngress=121 ConsEgress=151 Flags=Xover
				HF_4: ConsIngress=0   ConsEgress=612 Flags=VerifyOnly
			IF_2: ISD=1 Hops=3 Flags=ConsDir
				HF_5: ConsIngress=0   ConsEgress=621 Flags=VerifyOnly
				HF_6: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_7: ConsIngress=261 ConsEgress=0   Flags=Xover
		UDP_1: Src=40111 Dst=40222
	`)
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_3", "HF_4")

	// SCMP revocation reply (reversed SCION header) from the BR to the source of the packet.
	pkt1 := AllocatePacket()
	pkt1.SetDev("ifid_local")
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.13 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=30003 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=8 CurrHopF=11 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:5 Dst=172.16.5.1
			IF_1: ISD=1 Hops=3
				HF_1: ConsIngress=261 ConsEgress=0   Flags=Xover
				HF_2: ConsIngress=211 ConsEgress=0   Flags=Xover
				HF_3: ConsIngress=0   ConsEgress=621 Flags=VerifyOnly
			IF_2: ISD=1 Hops=4 Flags=ConsDir,Shortcut,Peer
				HF_4: ConsIngress=0   ConsEgress=612 Flags=VerifyOnly
				HF_5: ConsIngress=121 ConsEgress=151 Flags=Xover
				HF_6: ConsIngress=162 ConsEgress=151 Flags=Xover
				HF_7: ConsIngress=511 ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=REVOKED_IF Checksum=0
			InfoRevocation: InfoF=4 HopF=7 IfID=121 Ingress=false
				SignedRevInfo: IfID=121 IA=1-ff00:0:1 Link=peer TS=now TTL=10
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_2", "HF_5", "HF_4")
	pkt1.GenerateMac("SCION", "IF_2", "HF_6", "HF_4")

	SendPackets(pkt0)

	ret := ExpectedPackets("Revoked Peer Interface", defaultTimeout, pkt1)

	ifStateUp := ifStateDown.CloneAndUpdate(`
		IFStateInfo: Active=false
	`)
	SendPackets(ifStateUp)
	Sleep("250ms")

	return ret
}
