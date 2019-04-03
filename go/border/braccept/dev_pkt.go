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

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DevPkt struct {
	Dev string
	Pkt gopacket.Packet
}

func toGoPackets(pkts ...*DevTaggedLayers) []*DevPkt {
	goPkts := make([]*DevPkt, len(pkts))
	for i := range pkts {
		goPkts[i] = &DevPkt{Dev: pkts[i].Dev}
		raw := pkts[i].TaggedLayers.Serialize()
		goPkts[i].Pkt = gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.DecodeOptions{})
	}
	return goPkts
}
