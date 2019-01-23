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
	"github.com/scionproto/scion/go/lib/scmp"
)

var extnLayerID = 1360

func newExtnLayerID() int {
	id := extnLayerID
	extnLayerID += 1
	return id
}

var LayerTypeScionHBH gopacket.LayerType

func init() {
	// XXX(sgmonroy) Use init() to avoid initialization loop (HBH extension chaining)
	LayerTypeScionHBH = gopacket.RegisterLayerType(
		newExtnLayerID(),
		gopacket.LayerTypeMetadata{
			Name:    "ScionHopByHop",
			Decoder: gopacket.DecodeFunc(decodeScionHBH),
		},
	)
}

func decodeScionHBH(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < common.LineLen {
		p.SetTruncated()
		return fmt.Errorf("Invalid SCION HopByHop extension. Length %d less than %d",
			len(data), common.LineLen)
	}
	switch data[2] {
	case common.ExtnSCMPType.Type:
		return decodeHBHSCMP(data, p)
	}
	return fmt.Errorf("Unsupported SCION HopByHop extension. Type %d", data[2])
}

type baseExtension struct {
	NextHdr common.L4ProtocolType
	Length  uint8
	Type    uint8
}

func (l *baseExtension) decodeFromBytes(data []byte) {
	l.NextHdr = common.L4ProtocolType(data[0])
	l.Length = data[1]
	l.Type = data[2]
}

func (l *baseExtension) SerializeTo(data []byte) {
	data[0] = uint8(l.NextHdr)
	data[1] = l.Length
	data[2] = l.Type
}

func (l *baseExtension) LengthBytes() int {
	return int(l.Length) * common.LineLen
}

var _ LayerBuilder = (*ScionSCMPExtn)(nil)
var _ LayerMatcher = (*ScionSCMPExtn)(nil)

var LayerTypeScionHBHSCMP = gopacket.RegisterLayerType(
	newExtnLayerID(),
	gopacket.LayerTypeMetadata{
		Name:    "ScionHopByHopSCMP",
		Decoder: gopacket.DecodeFunc(decodeHBHSCMP),
	},
)

type ScionSCMPExtn struct {
	layers.BaseLayer
	baseExtension
	scmp.Extn
}

func NewSCMPExtn(nh common.L4ProtocolType, ext scmp.Extn) *ScionSCMPExtn {
	return &ScionSCMPExtn{
		baseExtension: baseExtension{NextHdr: nh, Length: 1, Type: common.ExtnSCMPType.Type},
		Extn:          ext,
	}
}

func (l *ScionSCMPExtn) Build() ([]gopacket.SerializableLayer, error) {
	return []gopacket.SerializableLayer{l}, nil
}

func (l *ScionSCMPExtn) Match(pktLayers []gopacket.Layer,
	lc *LayerCache) ([]gopacket.Layer, error) {

	e, ok := pktLayers[0].(*ScionSCMPExtn)
	if !ok {
		return nil, fmt.Errorf("Wrong layer\nExpected %v\nActual   %v",
			LayerTypeScionHBHSCMP, pktLayers[0].LayerType())
	}
	if l.Extn != e.Extn {
		return nil, fmt.Errorf("SCMP HopByHop extension does not match\nExpected %s\nActual   %s",
			gopacket.LayerString(l), gopacket.LayerString(e))
	}

	return pktLayers[1:], nil
}

func (l *ScionSCMPExtn) LayerType() gopacket.LayerType {
	return LayerTypeScionHBHSCMP
}

func (l *ScionSCMPExtn) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	buf, err := b.PrependBytes(l.LengthBytes())
	if err != nil {
		return err
	}
	l.baseExtension.SerializeTo(buf)
	if err := l.Extn.Write(buf[common.ExtnSubHdrLen:]); err != nil {
		return err
	}
	return nil
}

func (l *ScionSCMPExtn) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// data length is at least common.LineLen
	l.baseExtension.decodeFromBytes(data)
	e, err := scmp.ExtnFromRaw(data[3:])
	if err != nil {
		return err
	}
	l.Extn = *e
	length := l.LengthBytes()
	padding := data[4:length]
	if _, res := isZeroMemory(padding); !res {
		return fmt.Errorf("SCMP extension padding is not zero.\nActual %s", padding)
	}
	l.Contents = data[:length]
	l.Payload = data[length:]
	return nil
}

func decodeHBHSCMP(data []byte, p gopacket.PacketBuilder) error {
	s := &ScionSCMPExtn{}
	err := s.DecodeFromBytes(data, p)
	p.AddLayer(s)
	if err != nil {
		return err
	}
	return p.NextDecoder(scionNextLayerType(s.NextHdr))
}

func isZeroMemory(b common.RawBytes) (int, bool) {
	for i := range b {
		if b[i] != 0 {
			return i, false
		}
	}
	return 0, true
}
