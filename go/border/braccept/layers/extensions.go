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

package layers

import (
	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/layers"
)

type ScionHBH struct {
	layers.Extension
}

var LayerTypeScionHBH gopacket.LayerType

func init() {
	// XXX(sgmonroy) Use init() to avoid initialization loop (HBH extension chaining)
	LayerTypeScionHBH = gopacket.RegisterLayerType(
		1360,
		gopacket.LayerTypeMetadata{
			Name:    "ScionHopByHop",
			Decoder: gopacket.DecodeFunc(decodeScionHBH),
		},
	)
}

func (l *ScionHBH) LayerType() gopacket.LayerType {
	return LayerTypeScionHBH
}

func decodeScionHBH(data []byte, p gopacket.PacketBuilder) error {
	e := &ScionHBH{}
	err := e.DecodeFromBytes(data, p)
	p.AddLayer(e)
	if err != nil {
		return err
	}
	return p.NextDecoder(scionNextLayerType(e.NextHeader))
}

func (l *ScionHBH) LengthBytes() int {
	return int(l.NumLines) * common.LineLen
}
