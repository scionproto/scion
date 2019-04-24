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
	"fmt"

	"github.com/google/gopacket"
	golayers "github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spkt"
)

var scnLayerID = 1350

func newScnLayerID() int {
	id := scnLayerID
	scnLayerID += 1
	return id
}

// We need the NetworkLayer interface to support SetNetworkLayerForChecksum on L4 protocols
var _ gopacket.NetworkLayer = (*Scion)(nil)
var _ gopacket.SerializableLayer = (*Scion)(nil)
var _ gopacket.Layer = (*Scion)(nil)

// Scion represents the gopacket SCION network layer, which contains the common,
// address and path "headers".
type Scion struct {
	golayers.BaseLayer
	nextHdr common.L4ProtocolType
	CmnHdr  spkt.CmnHdr
	AddrHdr AddrHdr
	Path    ScnPath
}

var LayerTypeScion = gopacket.RegisterLayerType(
	newScnLayerID(),
	gopacket.LayerTypeMetadata{
		Name:    "SCION",
		Decoder: gopacket.DecodeFunc(decodeScion),
	},
)

func (l *Scion) LayerType() gopacket.LayerType {
	return LayerTypeScion
}

// XXX required to implement NetworkLayer interface
func (l *Scion) NetworkFlow() gopacket.Flow {
	return gopacket.Flow{}
}

func (l *Scion) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	scnLen := spkt.CmnHdrLen + l.AddrHdr.Len() + l.Path.Len()
	buf, err := b.PrependBytes(scnLen)
	if err != nil {
		return err
	}
	if opts.FixLengths {
		l.CmnHdr.HdrLen = uint8(scnLen / common.LineLen)
		l.CmnHdr.TotalLen = uint16(len(b.Bytes()))
	}
	l.CmnHdr.Write(buf)
	addrLen := l.AddrHdr.Write(buf[spkt.CmnHdrLen:])
	return l.Path.WriteTo(buf[spkt.CmnHdrLen+addrLen:])
}

func (l *Scion) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if err := l.CmnHdr.Parse(data); err != nil {
		return err
	}
	offset := spkt.CmnHdrLen
	addrLen, err := l.AddrHdr.Parse(data[offset:], l.CmnHdr.SrcType, l.CmnHdr.DstType)
	if err != nil {
		return err
	}
	offset += addrLen
	hdrLen := l.CmnHdr.HdrLenBytes()
	if hdrLen < offset || hdrLen > len(data) {
		return fmt.Errorf("Invalid Header Length: min %d, max %d, actual %d\n",
			offset, len(data), hdrLen)
	}
	if err := l.Path.Parse(data[offset:hdrLen]); err != nil {
		return err
	}
	l.Contents = data[:hdrLen]
	l.Payload = data[hdrLen:]
	l.nextHdr = l.CmnHdr.NextHdr
	return nil
}

func decodeScion(data []byte, p gopacket.PacketBuilder) error {
	scn := &Scion{}
	err := scn.DecodeFromBytes(data, p)
	p.AddLayer(scn)
	if err != nil {
		return err
	}
	return p.NextDecoder(scionNextLayerType(scn.nextHdr))
}

func scionNextLayerType(t common.L4ProtocolType) gopacket.LayerType {
	switch t {
	case common.HopByHopClass:
		return LayerTypeScionHBH
	case common.L4SCMP:
		return LayerTypeSCMP
	case common.L4UDP:
		return golayers.LayerTypeUDP
	}
	return gopacket.LayerTypePayload
}
