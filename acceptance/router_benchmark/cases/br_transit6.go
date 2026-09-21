// Copyright 2026 SCION Association
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

package cases

import (
	"hash"
	"time"

	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// BrTransit6 is the IPv6 underlay variant of BrTransit.
func BrTransit6(packetSize int, mac hash.Hash) (string, string, []byte, []byte) {

	var (
		originIA       = ISDAS(2)
		originIP       = PublicIP6(2, 1)
		originHost     = HostAddr(originIP)
		srcIP, srcPort = PublicIP6Port(2, 1)
		dstIP, dstPort = PublicIP6Port(1, 2)
		targetIA       = ISDAS(3)
		targetIP       = PublicIP6(3, 1)
		targetHost     = HostAddr(targetIP)
	)

	ethernet, ip, udp := Underlay6(srcIP, srcPort, dstIP, dstPort)

	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				Timestamp: util.TimeToSecs(time.Now()),
				ConsDir:   false,
			},
			{
				SegID:     0x222,
				Timestamp: util.TimeToSecs(time.Now()),
				ConsDir:   true,
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 1, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 2},
			{ConsIngress: 0, ConsEgress: 3},
			{ConsIngress: 1, ConsEgress: 0},
		},
	}

	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
	sp.HopFields[0].Mac = path.MAC(FakeMAC(2), sp.InfoFields[0], sp.HopFields[0], nil)

	sp.HopFields[2].Mac = path.MAC(mac, sp.InfoFields[1], sp.HopFields[2], nil)
	sp.InfoFields[1].UpdateSegID(sp.HopFields[2].Mac)
	sp.HopFields[3].Mac = path.MAC(FakeMAC(3), sp.InfoFields[1], sp.HopFields[2], nil)
	sp.InfoFields[1].SegID = 0x222

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        originIA,
		DstIA:        targetIA,
		Path:         sp,
	}
	if err := scionL.SetSrcAddr(originHost); err != nil {
		panic(err)
	}
	if err := scionL.SetDstAddr(targetHost); err != nil {
		panic(err)
	}

	scionudp := &slayers.UDP{}
	scionudp.SrcPort = 50000
	scionudp.DstPort = 50000
	scionudp.SetNetworkLayerForChecksum(scionL)

	payload, packet := mkPacket(packetSize, ethernet, ip, udp, scionL, scionudp)
	return DeviceName(1, 2), DeviceName(1, 3), payload, packet
}
