// Copyright 2020 Anapaya Systems
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

package slayers

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
)

// SCMPExternalInterfaceDown message contains the data for that error.
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |              ISD              |                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                        Interface ID                           +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type SCMPExternalInterfaceDown struct {
	layers.BaseLayer
	IA   addr.IA
	IfID uint64
}

// LayerType returns LayerTypeSCMPExternalInterfaceDown.
func (i *SCMPExternalInterfaceDown) LayerType() gopacket.LayerType {
	return LayerTypeSCMPExternalInterfaceDown
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (i *SCMPExternalInterfaceDown) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *SCMPExternalInterfaceDown) DecodeFromBytes(data []byte,
	df gopacket.DecodeFeedback) error {

	minLength := addr.IABytes + 8
	if size := len(data); size < minLength {
		df.SetTruncated()
		return serrors.New("buffer too short", "mininum_legth", minLength, "actual", size)
	}
	offset := 0
	i.IA = addr.IAFromRaw(data[offset:])
	offset += addr.IABytes
	i.IfID = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	i.BaseLayer = layers.BaseLayer{
		Contents: data[:offset],
		Payload:  data[offset:],
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (i *SCMPExternalInterfaceDown) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	buf, err := b.PrependBytes(addr.IABytes + 8)
	if err != nil {
		return err
	}
	offset := 0
	i.IA.Write(buf[offset:])
	offset += addr.IABytes
	binary.BigEndian.PutUint64(buf[offset:offset+8], i.IfID)
	return nil
}

func decodeSCMPExternalInterfaceDown(data []byte, pb gopacket.PacketBuilder) error {
	s := &SCMPExternalInterfaceDown{}
	err := s.DecodeFromBytes(data, pb)
	if err != nil {
		return err
	}
	pb.AddLayer(s)
	return pb.NextDecoder(gopacket.LayerTypePayload)
}
