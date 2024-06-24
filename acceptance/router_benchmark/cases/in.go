// Copyright 2023 SCION Association
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

// Topology (see accept/router_benchmark/conf/topology.json)
//    AS2 (br2) ---+== (br1a) AS1 (br1b) ---- (br4) AS4
//                 |
//    AS3 (br3) ---+
// See topo.go

// oneIn generates one packet of incoming traffic into AS1 at br1a. The outcome is a raw packet
// that the test must feed into the router. The flow ID is 0.
func In(packetSize int, mac hash.Hash) (string, string, []byte, []byte) {

	var (
		originIA       = ISDAS(2)
		originIP       = PublicIP(2, 1)
		originHost     = HostAddr(originIP)
		srcIP, srcPort = PublicIPPort(2, 1)
		dstIP, dstPort = PublicIPPort(1, 2)
		targetIA       = ISDAS(1)
		targetIP       = InternalIP(1, 2)
		targetHost     = HostAddr(targetIP)
	)

	ethernet, ip, udp := Underlay(srcIP, srcPort, dstIP, dstPort)

	// Fully correct (hopefully) path.
	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{2, 0, 0},
			},
			NumINF:  1,
			NumHops: 2,
		},
		InfoFields: []path.InfoField{
			{
				SegID:     0x111,
				Timestamp: util.TimeToSecs(time.Now()),
				ConsDir:   false,
			},
		},
		HopFields: []path.HopField{
			{ConsIngress: 1, ConsEgress: 0}, // From there (non-consdir)
			{ConsIngress: 0, ConsEgress: 2}, // <- Processed here (non-consdir)
		},
	}

	// Calculate MACs...
	// Seg0: Hops are in non-consdir.
	sp.HopFields[1].Mac = path.MAC(mac, sp.InfoFields[0], sp.HopFields[1], nil)
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)
	sp.HopFields[0].Mac = path.MAC(FakeMAC(2), sp.InfoFields[0], sp.HopFields[0], nil)

	// End-to-end. Src is the originator and Dst is the final destination.
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
	return DeviceName(1, 2), DeviceName(1, 0), payload, packet
}
