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

// UDP is the SCION/UDP header. It reuses layers.UDP as much as possible and only customizes
// checksum calculation.
type UDP struct {
	layers.UDP
	scn *SCION
}

func (u *UDP) LayerType() gopacket.LayerType {
	return LayerTypeSCIONUDP
}

func (u *UDP) CanDecode() gopacket.LayerClass {
	return LayerTypeSCIONUDP
}

func (u *UDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, uint16(u.SrcPort))
	binary.BigEndian.PutUint16(bytes[2:], uint16(u.DstPort))
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
		u.Checksum, err = u.scn.computeChecksum(b.Bytes(), uint8(common.L4UDP))
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

func (u *UDP) SetNetworkLayerForChecksum(l gopacket.NetworkLayer) error {
	if l.LayerType() == LayerTypeSCION {
		u.scn = l.(*SCION)
		return nil
	}
	return u.UDP.SetNetworkLayerForChecksum(l)
}

func (u *UDP) String() string {
	return fmt.Sprintf("SrcPort=%s, DstPort=%s", u.SrcPort, u.DstPort)
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
