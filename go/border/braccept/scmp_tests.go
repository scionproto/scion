// Copyright 2019 Anapaya Systems
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
// See the License for the specdic language governing permissions and
// limitations under the License.

package main

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

type scmpTestCfg struct {
	LocalInterface common.IFIDType
	DstIA          addr.IA
}

// scmpBadVersion sends a packet with a bad version and checks that this packet
// gets dropped.
func (c scmpTestCfg) scmpBadVersion() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: Ver=8 NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad version", defaultTimeout)
}

// scmpBadDstType sends a packet with a bad destination type and checks that
// this packets gets dropped.
func (c scmpTestCfg) scmpBadDstType() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=5
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad dst type", defaultTimeout)
}

// scmpBadSrcType sends a packet with a bad source type and checks that this
// packet gets dropped.
func (c scmpTestCfg) scmpBadSrcType() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=5 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad src type", defaultTimeout)
}

func (c scmpTestCfg) scmpBadPktLenShort() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4 TotalLen=63 HdrLen=7
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=%d ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=CMNHDR Type=BAD_PKT_LEN Checksum=0
			InfoPktSize: Size=64 MTU=1472
			QUOTED: RawPkt=%s
	`, c.LocalInterface, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad pkt len (too short)", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpBadPktLenLong() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4 TotalLen=65 HdrLen=7
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=%d ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=CMNHDR Type=BAD_PKT_LEN Checksum=0
			InfoPktSize: Size=64 MTU=1472
			QUOTED: RawPkt=%s
	`, c.LocalInterface, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad pkt len (too long)", defaultTimeout, pkt1)
}

// scmpBadHdrLenShort sends a packet with a bad hdr len and checks that this
// packet gets dropped.
func (c scmpTestCfg) scmpBadHdrLenShort() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4 TotalLen=64 HdrLen=6
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad hdr len (too short)", defaultTimeout)
}

// scmpBadHdrLenLong sends a packet with a bad hdr len and checks that this
// packet gets dropped.
func (c scmpTestCfg) scmpBadHdrLenLong() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4 TotalLen=64 HdrLen=8
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad hdr len (too long)", defaultTimeout)
}

func (c scmpTestCfg) scmpBadInfoFieldOffsetLow() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=3 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=0 CurrHopF=0 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=CMNHDR Type=BAD_IOF_OFFSET Checksum=0
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad infoF offset (low)", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpBadInfoFieldOffsetHigh() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=255 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=0 CurrHopF=0 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=CMNHDR Type=BAD_IOF_OFFSET Checksum=0
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad infoF offset (high)", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpBadHopFieldOffsetLow() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=1 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=0 CurrHopF=0 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=CMNHDR Type=BAD_HOF_OFFSET Checksum=0
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad hop field offset (low)", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpBadHopFieldOffsetHigh() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=255 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=0 CurrHopF=0 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=CMNHDR Type=BAD_HOF_OFFSET Checksum=0
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad hop field offset (high)", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpPathRequired() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=0 CurrHopF=0 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
		UDP_1:
	`, c.DstIA))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=0 CurrHopF=0 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=PATH_REQUIRED Checksum=0
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("scmp path required", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpBadMac() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0 Mac=007700
				HF_2: ConsIngress=0   ConsEgress=311 Mac=c0beef
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.SetChecksum("UDP", "IP4")
	// invalid mac

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311 Mac=c0beef
				HF_2: ConsIngress=%d ConsEgress=0 Mac=007700
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=BAD_MAC Checksum=0
			InfoPathOffsets: InfoF=4 HopF=5 IfID=%d Ingress=false
			QUOTED: RawPkt=%s
	`, c.LocalInterface, c.LocalInterface, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad hop field offset (high)", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpExpiredHopField() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2 TsInt=0
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir TsInt=0
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=%d ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=EXPIRED_HOPF Checksum=0
			InfoPathOffsets: InfoF=4 HopF=5 IfID=%d Ingress=false
			QUOTED: RawPkt=%s
	`, c.LocalInterface, c.LocalInterface, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp expired hop field", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpBadInterface() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=1-ff00:0:1 Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=666 ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=666 ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=BAD_IF Checksum=0
			InfoPathOffsets: InfoF=4 HopF=5 IfID=666 Ingress=false
			QUOTED: RawPkt=%s
	`, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad interface", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpNonRoutingHopField() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=UDP CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0 Flags=VerifyOnly
				HF_2: ConsIngress=0   ConsEgress=311
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=%d ConsEgress=0 Flags=VerifyOnly
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=PATH Type=NON_ROUTING_HOPF Checksum=0
			InfoPathOffsets: InfoF=4 HopF=5 IfID=%d Ingress=false
			QUOTED: RawPkt=%s
	`, c.LocalInterface, c.LocalInterface, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp non routing hop field", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpTooManyHopByHop() int {
	// add more than 3 (cmmon.ExtnMaxHBH) extensions
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		HBH: NextHdr=HBH Type=OHP
			HBH.Empty:
		HBH: NextHdr=HBH Type=OHP
			HBH.Empty:
		HBH: NextHdr=HBH Type=OHP
			HBH.Empty:
		HBH: NextHdr=UDP Type=OHP
			HBH.Empty:
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=%d ConsEgress=0
		HBH: NextHdr=HBH Type=SCMP
			HBH.SCMP: Flags=Error
		HBH: NextHdr=HBH Type=OHP
			HBH.Empty:
		HBH: NextHdr=HBH Type=OHP
			HBH.Empty:
		HBH: NextHdr=SCMP Type=OHP
			HBH.OHP:
		SCMP: Class=EXT Type=TOO_MANY_HOPBYHOP Checksum=0
			InfoExtIdx: Idx=4
			QUOTED: RawPkt=%s
	`, c.LocalInterface, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp too many HbH extensions", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpBadExtensionOrder() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		HBH: NextHdr=HBH Type=OHP
			HBH.OHP:
		HBH: NextHdr=UDP Type=SCMP
			HBH.SCMP:
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=%d ConsEgress=0
		HBH: NextHdr=HBH Type=SCMP
			HBH.SCMP: Flags=Error
		HBH: NextHdr=SCMP Type=OHP
			HBH.OHP:
		SCMP: Class=EXT Type=BAD_EXT_ORDER Checksum=0
			InfoExtIdx: Idx=1
			QUOTED: RawPkt=%s
	`, c.LocalInterface, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad extension order", defaultTimeout, pkt1)
}

func (c scmpTestCfg) scmpBadHopByHop() int {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:be:ef DstMAC=f0:0d:ca:fe:00:01 EthernetType=IPv4
		IP4: Src=192.168.0.61 Dst=192.168.0.11 NextHdr=UDP Flags=DF
		UDP: Src=20006 Dst=30001
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=5 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.61 DstIA=%s Dst=172.16.3.1
			IF_1: ISD=1 Hops=2
				HF_1: ConsIngress=%d ConsEgress=0
				HF_2: ConsIngress=0   ConsEgress=311
		HBH: NextHdr=UDP Type=InvHBH
			HBH.Empty:
		UDP_1:
	`, c.DstIA, c.LocalInterface))
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")
	pkt0.GenerateMac("SCION", "IF_1", "HF_1", "HF_2")

	pkt1 := AllocatePacket()
	pkt1.ParsePacket(fmt.Sprintf(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30001 Dst=20006 Checksum=0
		SCION: NextHdr=HBH CurrInfoF=4 CurrHopF=6 SrcType=IPv4 DstType=IPv4
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.11 DstIA=1-ff00:0:1 Dst=192.168.0.61
			IF_1: ISD=1 Hops=2 Flags=ConsDir
				HF_1: ConsIngress=0   ConsEgress=311
				HF_2: ConsIngress=%d ConsEgress=0
		HBH: NextHdr=SCMP Type=SCMP
			HBH.SCMP: Flags=Error,HBH
		SCMP: Class=EXT Type=BAD_HOPBYHOP Checksum=0
			InfoExtIdx: Idx=0
			QUOTED: RawPkt=%s
	`, c.LocalInterface, pkt0.Serialize()))
	pkt1.SetDev("veth_int")
	pkt1.SetChecksum("UDP", "IP4")
	pkt1.SetChecksum("SCMP", "SCION")
	pkt1.GenerateMac("SCION", "IF_1", "HF_2", "HF_1")

	SendPackets(pkt0)

	return ExpectedPackets("scmp bad hop by hop extension", defaultTimeout, pkt1)
}
