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

const scmpRawInterfaceLen = 8

// SCMPExternalInterfaceDown message contains the data for that error.
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |              ISD              |                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                        Interface ID                           +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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

	minLength := addr.IABytes + scmpRawInterfaceLen
	if size := len(data); size < minLength {
		df.SetTruncated()
		return serrors.New("buffer too short", "mininum_legth", minLength, "actual", size)
	}
	offset := 0
	i.IA = addr.IAFromRaw(data[offset:])
	offset += addr.IABytes
	i.IfID = binary.BigEndian.Uint64(data[offset : offset+scmpRawInterfaceLen])
	offset += scmpRawInterfaceLen
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

	buf, err := b.PrependBytes(addr.IABytes + scmpRawInterfaceLen)
	if err != nil {
		return err
	}
	offset := 0
	i.IA.Write(buf[offset:])
	offset += addr.IABytes
	binary.BigEndian.PutUint64(buf[offset:offset+scmpRawInterfaceLen], i.IfID)
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

// SCMPInternalConnectivityDown indicates the AS internal connection between 2
// routers is down. The format is as follows:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |              ISD              |                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                   Ingress Interface ID                        +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                   Egress Interface ID                         +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type SCMPInternalConnectivityDown struct {
	layers.BaseLayer
	IA      addr.IA
	Ingress uint64
	Egress  uint64
}

// LayerType returns LayerTypeSCMPInternalConnectivityDown.
func (*SCMPInternalConnectivityDown) LayerType() gopacket.LayerType {
	return LayerTypeSCMPInternalConnectivityDown
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*SCMPInternalConnectivityDown) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *SCMPInternalConnectivityDown) DecodeFromBytes(data []byte,
	df gopacket.DecodeFeedback) error {

	minLength := addr.IABytes + 2*scmpRawInterfaceLen
	if size := len(data); size < minLength {
		df.SetTruncated()
		return serrors.New("buffer too short", "mininum_legth", minLength, "actual", size)
	}
	offset := 0
	i.IA = addr.IAFromRaw(data[offset:])
	offset += addr.IABytes
	i.Ingress = binary.BigEndian.Uint64(data[offset : offset+scmpRawInterfaceLen])
	offset += scmpRawInterfaceLen
	i.Egress = binary.BigEndian.Uint64(data[offset : offset+scmpRawInterfaceLen])
	offset += scmpRawInterfaceLen
	i.BaseLayer = layers.BaseLayer{
		Contents: data[:offset],
		Payload:  data[offset:],
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (i *SCMPInternalConnectivityDown) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	buf, err := b.PrependBytes(addr.IABytes + 2*scmpRawInterfaceLen)
	if err != nil {
		return err
	}
	offset := 0
	i.IA.Write(buf[offset:])
	offset += addr.IABytes
	binary.BigEndian.PutUint64(buf[offset:offset+scmpRawInterfaceLen], i.Ingress)
	offset += scmpRawInterfaceLen
	binary.BigEndian.PutUint64(buf[offset:offset+scmpRawInterfaceLen], i.Egress)
	return nil
}

func decodeSCMPInternalConnectivityDown(data []byte, pb gopacket.PacketBuilder) error {
	s := &SCMPInternalConnectivityDown{}
	if err := s.DecodeFromBytes(data, pb); err != nil {
		return err
	}
	pb.AddLayer(s)
	return pb.NextDecoder(s.NextLayerType())
}

// SCMPEcho represents the structure of a ping.
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |        Sequence Number        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type SCMPEcho struct {
	layers.BaseLayer
	Identifier uint16
	SeqNumber  uint16
}

// LayerType returns LayerTypeSCMPEcho.
func (*SCMPEcho) LayerType() gopacket.LayerType {
	return LayerTypeSCMPEcho
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*SCMPEcho) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *SCMPEcho) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	minLength := 4
	if size := len(data); size < minLength {
		df.SetTruncated()
		return serrors.New("buffer too short", "min", minLength, "actual", size)
	}
	offset := 0
	i.Identifier = binary.BigEndian.Uint16(data[:2])
	offset += 2
	i.SeqNumber = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	i.BaseLayer = layers.BaseLayer{
		Contents: data[:offset],
		Payload:  data[offset:],
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (i *SCMPEcho) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	buf, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	offset := 0
	binary.BigEndian.PutUint16(buf[:2], i.Identifier)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:offset+2], i.SeqNumber)
	return nil
}

func decodeSCMPEcho(data []byte, pb gopacket.PacketBuilder) error {
	s := &SCMPEcho{}
	if err := s.DecodeFromBytes(data, pb); err != nil {
		return err
	}
	pb.AddLayer(s)
	return pb.NextDecoder(s.NextLayerType())
}

// SCMPParameterProblem represents the structure of a parameter problem message.
//
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |            reserved           |           Pointer             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type SCMPParameterProblem struct {
	layers.BaseLayer
	Pointer uint16
}

// LayerType returns LayerTypeSCMPParameterProblem.
func (*SCMPParameterProblem) LayerType() gopacket.LayerType {
	return LayerTypeSCMPParameterProblem
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*SCMPParameterProblem) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *SCMPParameterProblem) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	minLength := 2 + 2
	if size := len(data); size < minLength {
		df.SetTruncated()
		return serrors.New("buffer too short", "min", minLength, "actual", size)
	}
	i.Pointer = binary.BigEndian.Uint16(data[2:4])
	i.BaseLayer = layers.BaseLayer{
		Contents: data[:4],
		Payload:  data[4:],
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (i *SCMPParameterProblem) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	buf, err := b.PrependBytes(2 + 2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(buf[0:2], uint16(0)) //Reserved
	binary.BigEndian.PutUint16(buf[2:4], i.Pointer)
	return nil
}

func decodeSCMPParameterProblem(data []byte, pb gopacket.PacketBuilder) error {
	s := &SCMPParameterProblem{}
	if err := s.DecodeFromBytes(data, pb); err != nil {
		return err
	}
	pb.AddLayer(s)
	return pb.NextDecoder(s.NextLayerType())
}

// SCMPTraceroute represents the structure of a traceroute.
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |        Sequence Number        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |              ISD              |                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                        Interface ID                           +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type SCMPTraceroute struct {
	layers.BaseLayer
	Identifier uint16
	Sequence   uint16
	IA         addr.IA
	Interface  uint64
}

// LayerType returns LayerTypeSCMPTraceroute.
func (*SCMPTraceroute) LayerType() gopacket.LayerType {
	return LayerTypeSCMPTraceroute
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*SCMPTraceroute) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *SCMPTraceroute) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	minLength := 2 + 2 + addr.IABytes + scmpRawInterfaceLen
	if size := len(data); size < minLength {
		df.SetTruncated()
		return serrors.New("buffer too short", "min", minLength, "actual", size)
	}
	offset := 0
	i.Identifier = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	i.Sequence = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	i.IA = addr.IAFromRaw(data[offset : offset+addr.IABytes])
	offset += addr.IABytes
	i.Interface = binary.BigEndian.Uint64(data[offset : offset+scmpRawInterfaceLen])
	offset += scmpRawInterfaceLen
	i.BaseLayer = layers.BaseLayer{
		Contents: data[:offset],
		Payload:  data[offset:],
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (i *SCMPTraceroute) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	buf, err := b.PrependBytes(2 + 2 + addr.IABytes + scmpRawInterfaceLen)
	if err != nil {
		return err
	}
	offset := 0
	binary.BigEndian.PutUint16(buf[:2], i.Identifier)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:offset+2], i.Sequence)
	offset += 2
	i.IA.Write(buf[offset : offset+addr.IABytes])
	offset += addr.IABytes
	binary.BigEndian.PutUint64(buf[offset:offset+scmpRawInterfaceLen], i.Interface)
	return nil
}

func decodeSCMPTraceroute(data []byte, pb gopacket.PacketBuilder) error {
	s := &SCMPTraceroute{}
	if err := s.DecodeFromBytes(data, pb); err != nil {
		return err
	}
	pb.AddLayer(s)
	return pb.NextDecoder(s.NextLayerType())
}

// SCMPDestinationUnreachable represents the structure of a destination
// unreachable message.
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             Unused                            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type SCMPDestinationUnreachable struct {
	layers.BaseLayer
}

// LayerType returns LayerTypeSCMPTraceroute.
func (*SCMPDestinationUnreachable) LayerType() gopacket.LayerType {
	return LayerTypeSCMPDestinationUnreachable
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*SCMPDestinationUnreachable) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *SCMPDestinationUnreachable) DecodeFromBytes(data []byte,
	df gopacket.DecodeFeedback) error {

	minLength := 4
	if size := len(data); size < minLength {
		df.SetTruncated()
		return serrors.New("buffer too short", "min", minLength, "actual", size)
	}
	i.BaseLayer = layers.BaseLayer{
		Contents: data[:minLength],
		Payload:  data[minLength:],
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (i *SCMPDestinationUnreachable) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	buf, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	copy(buf, make([]byte, 4))
	return nil
}

func decodeSCMPDestinationUnreachable(data []byte, pb gopacket.PacketBuilder) error {
	s := &SCMPDestinationUnreachable{}
	if err := s.DecodeFromBytes(data, pb); err != nil {
		return err
	}
	pb.AddLayer(s)
	return pb.NextDecoder(s.NextLayerType())
}

// SCMPPacketTooBig represents the structure of a packet too big message.
//
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |            reserved           |             MTU               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type SCMPPacketTooBig struct {
	layers.BaseLayer
	MTU uint16
}

// LayerType returns LayerTypeSCMPParameterProblem.
func (*SCMPPacketTooBig) LayerType() gopacket.LayerType {
	return LayerTypeSCMPPacketTooBig
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (*SCMPPacketTooBig) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *SCMPPacketTooBig) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	minLength := 2 + 2
	if size := len(data); size < minLength {
		df.SetTruncated()
		return serrors.New("buffer too short", "min", minLength, "actual", size)
	}
	i.MTU = binary.BigEndian.Uint16(data[2:4])
	i.BaseLayer = layers.BaseLayer{
		Contents: data[:4],
		Payload:  data[4:],
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (i *SCMPPacketTooBig) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	buf, err := b.PrependBytes(2 + 2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(buf[0:2], uint16(0)) //Reserved
	binary.BigEndian.PutUint16(buf[2:4], i.MTU)
	return nil
}

func decodeSCMPPacketTooBig(data []byte, pb gopacket.PacketBuilder) error {
	s := &SCMPPacketTooBig{}
	if err := s.DecodeFromBytes(data, pb); err != nil {
		return err
	}
	pb.AddLayer(s)
	return pb.NextDecoder(s.NextLayerType())
}
