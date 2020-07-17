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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
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
	if !opts.ComputeChecksums || u.scn == nil {
		return u.UDP.SerializeTo(b, opts)
	}

	dstAddrBytes := addrBytes(u.scn.DstAddrLen)
	srcAddrBytes := addrBytes(u.scn.SrcAddrLen)
	addrHdrLen := 2*addr.IABytes + dstAddrBytes + srcAddrBytes
	pseudo := make([]byte, addrHdrLen+2+6)
	binary.BigEndian.PutUint16(pseudo[0:], uint16(common.L4UDP))
	binary.BigEndian.PutUint16(pseudo[2:], uint16(u.SrcPort))
	binary.BigEndian.PutUint16(pseudo[4:], uint16(u.DstPort))
	if opts.FixLengths {
		u.Length = uint16(len(b.Bytes()) + 8)
	}
	binary.BigEndian.PutUint16(pseudo[6:], u.Length)
	offset := 8
	u.scn.DstIA.Write(pseudo[offset:])
	offset += addr.IABytes
	u.scn.SrcIA.Write(pseudo[offset:])
	offset += addr.IABytes
	offset += copy(pseudo[offset:], u.scn.rawDstAddr)
	copy(pseudo[offset:], u.scn.rawSrcAddr)
	u.Checksum = util.Checksum(pseudo, b.Bytes())
	opts.ComputeChecksums = false

	return u.UDP.SerializeTo(b, opts)
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
