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
	golayers "github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
)

// UDP is a wrapper around layers.UDP to be able to leverage gopacket UDP checksum calculation
type UDP struct {
	golayers.UDP
	scn *Scion
}

func (udp *UDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if opts.ComputeChecksums && udp.scn != nil {
		// XXX An alternative method to calculate the checksum would be to let gopacket do it.
		// For that, we could generate a fake IPv4 header, with the SCION address header
		// partial checksum stored in the IPv4 header, ie. SrcIP.
		// There is an inconsistency that makes this a bit more ugly and is that UDP/TCP
		// checksum on IPv4/IPv6 also stores the computed UDP/TCP payload length in the pseudo
		// header and we do not do that for SCION, so we would need to offset that value for
		// gopacket to generate the correct checksum.
		pseudo := make(common.RawBytes, udp.scn.AddrHdr.Len()+2+6)
		common.Order.PutUint16(pseudo[0:], uint16(common.L4UDP))
		common.Order.PutUint16(pseudo[2:], uint16(udp.SrcPort))
		common.Order.PutUint16(pseudo[4:], uint16(udp.DstPort))
		if opts.FixLengths {
			common.Order.PutUint16(pseudo[6:], uint16(len(b.Bytes())+8))
		} else {
			common.Order.PutUint16(pseudo[6:], udp.Length)
		}

		udp.scn.AddrHdr.Write(pseudo[8:])
		udp.Checksum = util.Checksum(pseudo, b.Bytes())
		opts.ComputeChecksums = false
	}
	return udp.UDP.SerializeTo(b, opts)
}

func (udp *UDP) SetNetworkLayerForChecksum(l gopacket.NetworkLayer) error {
	if l.LayerType() == LayerTypeScion {
		udp.scn = l.(*Scion)
		return nil
	}
	return udp.UDP.SetNetworkLayerForChecksum(l)
}
