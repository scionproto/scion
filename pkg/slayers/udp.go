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

	"github.com/gopacket/gopacket"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// UDP is the SCION/UDP header.
// Note; this _could_ mostly reuse gopacket/layers.UDP and only customize
// checksum calculation, but as this pulls in every layer available in
// gopacket, we avoid this and implement it manually (i.e. copy-paste).
type UDP struct {
	BaseLayer
	SrcPort, DstPort uint16
	Length           uint16
	Checksum         uint16
	sPort, dPort     []byte
	scn              *SCION
}

func (u *UDP) LayerType() gopacket.LayerType {
	return LayerTypeSCIONUDP
}

func (u *UDP) CanDecode() gopacket.LayerClass {
	return LayerClassSCIONUDP
}

func (u *UDP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (u *UDP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointUDPPort, u.sPort, u.dPort)
}

// DecodeFromBytes implements the gopacket.DecodingLayer.DecodeFromBytes method.
// This implementation is copied from gopacket/layers/udp.go.
func (u *UDP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return fmt.Errorf("Invalid UDP header. Length %d less than 8", len(data))
	}
	u.SrcPort = binary.BigEndian.Uint16(data[0:2])
	u.sPort = data[0:2]
	u.DstPort = binary.BigEndian.Uint16(data[2:4])
	u.dPort = data[2:4]
	u.Length = binary.BigEndian.Uint16(data[4:6])
	u.Checksum = binary.BigEndian.Uint16(data[6:8])
	u.BaseLayer = BaseLayer{Contents: data[:8]}
	switch {
	case u.Length >= 8:
		hlen := int(u.Length)
		if hlen > len(data) {
			df.SetTruncated()
			hlen = len(data)
		}
		u.Payload = data[8:hlen]
	case u.Length == 0: // Jumbogram, use entire rest of data
		u.Payload = data[8:]
	default:
		return fmt.Errorf("UDP packet too small: %d bytes", u.Length)
	}
	return nil
}

func (u *UDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, u.SrcPort)
	binary.BigEndian.PutUint16(bytes[2:], u.DstPort)
	if opts.FixLengths {
		u.fixLengths(len(b.Bytes()))
	}
	binary.BigEndian.PutUint16(bytes[4:], u.Length)
	if opts.ComputeChecksums {
		if u.scn == nil {
			return serrors.New("can not calculate checksum without SCION header")
		}
		// zero out checksum bytes
		bytes[6] = 0
		bytes[7] = 0
		u.Checksum, err = u.scn.computeChecksum(b.Bytes(), uint8(L4UDP))
		if err != nil {
			return err
		}
	}
	binary.BigEndian.PutUint16(bytes[6:], u.Checksum)
	return nil
}

func (u *UDP) fixLengths(length int) {
	if length > 65535 {
		u.Length = 0
		return
	}
	u.Length = uint16(length)
}

func (u *UDP) SetNetworkLayerForChecksum(scn *SCION) {
	u.scn = scn
}

func (u *UDP) String() string {
	return fmt.Sprintf("SrcPort=%d, DstPort=%d", u.SrcPort, u.DstPort)
}

func decodeSCIONUDP(data []byte, pb gopacket.PacketBuilder) error {
	u := &UDP{}
	err := u.DecodeFromBytes(data, pb)
	pb.AddLayer(u)
	pb.SetTransportLayer(u)
	if err != nil {
		return err
	}
	return pb.NextDecoder(gopacket.LayerTypePayload)
}
