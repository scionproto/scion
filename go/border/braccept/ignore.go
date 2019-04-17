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

var IgnoredPkts []*DevPkt

func IgnoredPackets(dtls ...*DevTaggedLayers) {
	pkts := toGoPackets(dtls...)
	IgnoredPkts = append(IgnoredPkts, pkts...)
}

func ClearIgnoredPackets() {
	IgnoredPkts = IgnoredPkts[:0]
}

func IgnorePkts() {
	pkt0 := AllocatePacket()
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=f0:0d:ca:fe:00:01 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30041 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.101 DstIA=1-ff00:0:1 Dst=BS_M
		UDP_1: Src=20001 Dst=0
		IFStateReq:
	`)
	pkt0.SetDev("veth_int")
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")

	IgnoredPackets(pkt0)
}
