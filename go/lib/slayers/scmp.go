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
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// MaxSCMPPacketLen the maximum length a SCION packet including SCMP quote can
// have. This length includes the SCION, and SCMP header of the packet.
//
//  +-------------------------+
//  |        Underlay         |
//  +-------------------------+
//  |          SCION          |  \
//  |          SCMP           |   \
//  +-------------------------+    \_ MaxSCMPPacketLen
//  |          Quote:         |    /
//  |        SCION Orig       |   /
//  |         L4 Orig         |  /
//  +-------------------------+
const MaxSCMPPacketLen = 1232

// SCMP is the SCMP header on top of SCION header.
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |           Checksum            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                            InfoBlock                          |
//  +                                                               +
//  |                         (variable length)                     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                            DataBlock                          |
//  +                                                               +
//  |                         (variable length)                     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type SCMP struct {
	layers.BaseLayer
	TypeCode SCMPTypeCode
	Checksum uint16

	scn *SCION
}

// LayerType returns LayerTypeSCMP.
func (s *SCMP) LayerType() gopacket.LayerType {
	return LayerTypeSCMP
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (s *SCMP) CanDecode() gopacket.LayerClass {
	return LayerTypeSCMP
}

// NextLayerType use the typecode to select the right next decoder.
// If the SCMP type is unknown, the next layer is gopacket.LayerTypePayload.
func (s *SCMP) NextLayerType() gopacket.LayerType {
	switch s.TypeCode.Type() {
	case SCMPTypeDestinationUnreachable:
		return LayerTypeSCMPDestinationUnreachable
	case SCMPTypePacketTooBig:
		return LayerTypeSCMPPacketTooBig
	case SCMPTypeParameterProblem:
		return LayerTypeSCMPParameterProblem
	case SCMPTypeExternalInterfaceDown:
		return LayerTypeSCMPExternalInterfaceDown
	case SCMPTypeInternalConnectivityDown:
		return LayerTypeSCMPInternalConnectivityDown
	case SCMPTypeEchoRequest, SCMPTypeEchoReply:
		return LayerTypeSCMPEcho
	case SCMPTypeTracerouteRequest, SCMPTypeTracerouteReply:
		return LayerTypeSCMPTraceroute
	}
	return gopacket.LayerTypePayload
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (s *SCMP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	s.TypeCode.SerializeTo(bytes)

	if opts.ComputeChecksums {
		if s.scn == nil {
			return serrors.New("can not calculate checksum without SCION header")
		}
		// zero out checksum bytes
		bytes[2] = 0
		bytes[3] = 0
		s.Checksum, err = s.scn.computeChecksum(b.Bytes(), uint8(common.L4SCMP))
		if err != nil {
			return err
		}

	}
	binary.BigEndian.PutUint16(bytes[2:], s.Checksum)
	return nil
}

// DecodeFromBytes decodes the given bytes into this layer.
func (s *SCMP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if size := len(data); size < 4 {
		df.SetTruncated()
		return serrors.New("SCMP layer length is less then 4 bytes", "minimum", 4, "actual", size)
	}
	s.TypeCode = CreateSCMPTypeCode(SCMPType(data[0]), SCMPCode(data[1]))
	s.Checksum = binary.BigEndian.Uint16(data[2:4])
	s.BaseLayer = layers.BaseLayer{Contents: data[:4], Payload: data[4:]}
	return nil
}

func (s *SCMP) String() string {
	return fmt.Sprintf("%s(%d)\nPayload: %s", &s.TypeCode, s.Checksum, s.Payload)
}

// SetNetworkLayerForChecksum tells this layer which network layer is wrapping it.
// This is needed for computing the checksum when serializing,
func (s *SCMP) SetNetworkLayerForChecksum(l gopacket.NetworkLayer) error {
	if l == nil {
		return serrors.New("cannot use nil layer type for scmp checksum network layer")
	}
	if l.LayerType() != LayerTypeSCION {
		return serrors.New("cannot use layer type for scmp checksum network layer",
			"type", l.LayerType())
	}
	s.scn = l.(*SCION)
	return nil
}

func decodeSCMP(data []byte, pb gopacket.PacketBuilder) error {
	scmp := &SCMP{}
	err := scmp.DecodeFromBytes(data, pb)
	if err != nil {
		return err
	}
	pb.AddLayer(scmp)
	return pb.NextDecoder(scmp.NextLayerType())
}
