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

package tpkt

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spkt"
)

var scnLayerID = 1350

func newScnLayerID() int {
	id := scnLayerID
	scnLayerID += 1
	return id
}

var _ LayerMatcher = (*ScionLayer)(nil)

// ScionLayer represents the gopacket SCION network layer, which contains the common,
// address and path "headers".
type ScionLayer struct {
	layers.BaseLayer
	nextHdr common.L4ProtocolType
	CmnHdr  spkt.CmnHdr
	AddrHdr AddrHdr
	Path    ScnPath
}

var LayerTypeScion = gopacket.RegisterLayerType(
	newScnLayerID(),
	gopacket.LayerTypeMetadata{
		Name:    "SCION",
		Decoder: gopacket.DecodeFunc(decodeScionLayer),
	},
)

func (l *ScionLayer) LayerType() gopacket.LayerType {
	return LayerTypeScion
}

func (l *ScionLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	scnLen := spkt.CmnHdrLen + l.AddrHdr.Len() + l.Path.Segs.Len()
	buf, err := b.PrependBytes(scnLen)
	if err != nil {
		return err
	}
	l.CmnHdr.Write(buf)
	addrLen := l.AddrHdr.Write(buf[spkt.CmnHdrLen:])
	copy(buf[spkt.CmnHdrLen+addrLen:], l.Path.Raw)
	return nil
}

func (l *ScionLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
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
	rawPath := data[offset:hdrLen]
	if len(rawPath) > 0 {
		if err := l.Path.Parse(rawPath); err != nil {
			return err
		}
		l.Path.Raw = rawPath
		l.Path.InfOff = int(l.CmnHdr.CurrInfoF*common.LineLen) - offset
		l.Path.HopOff = int(l.CmnHdr.CurrHopF*common.LineLen) - offset
	}
	l.Contents = data[:hdrLen]
	l.Payload = data[hdrLen:]
	l.nextHdr = l.CmnHdr.NextHdr
	return nil
}

func (l *ScionLayer) Match(pktLayers []gopacket.Layer, lc *LayerCache) ([]gopacket.Layer, error) {
	scn, ok := pktLayers[0].(*ScionLayer)
	if !ok {
		return nil, fmt.Errorf("Wrong layer\nExpected %v\nActual   %v",
			LayerTypeScion, pktLayers[0].LayerType())
	}
	hdrLenBytes := int(l.CmnHdr.HdrLen * common.LineLen)
	if len(scn.LayerContents()) != hdrLenBytes {
		return nil, fmt.Errorf("Bad SCION header len, expected %d, actual   %d",
			hdrLenBytes, len(scn.LayerContents()))
	}
	if l.CmnHdr != scn.CmnHdr {
		return nil, fmt.Errorf("Common header mismatch\nExpected %v\nActual   %v",
			&l.CmnHdr, &scn.CmnHdr)
	}
	if !l.AddrHdr.Eq(&scn.AddrHdr) {
		return nil, fmt.Errorf("Address header mismatch\nExpected %v\nActual   %v",
			&l.AddrHdr, &scn.AddrHdr)
	}
	if err := l.Path.Check(&scn.Path); err != nil {
		return nil, err
	}
	// Add SCION to the layer cache in case that upper layers need to reference it
	lc.scion = scn
	return pktLayers[1:], nil
}

func (l *ScionLayer) RawAddrHdr() common.RawBytes {
	return l.Contents[spkt.CmnHdrLen : spkt.CmnHdrLen+l.AddrHdr.Len()]
}

func decodeScionLayer(data []byte, p gopacket.PacketBuilder) error {
	scn := &ScionLayer{}
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
	case common.L4UDP:
		return layers.LayerTypeUDP
	case common.L4SCMP:
		return LayerTypeSCMP
	}
	return gopacket.LayerTypePayload
}
