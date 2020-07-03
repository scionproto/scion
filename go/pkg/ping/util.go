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

package ping

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spkt"
)

// SizeLegacy computes the full SCION packet size for an address pair with a
// given payload size.
//
// Deprecated: This calculates the size of the SCMP packet with header v1.
// This function will be deleted when we switch to header v2 completely.
func SizeLegacy(local, remote *snet.UDPAddr, pldSize int) (int, error) {
	pkt, err := newEcho(local, remote, pldSize, scmp.InfoEcho{})
	if err != nil {
		return 0, err
	}
	raw := make([]byte, common.MaxMTU)
	n, err := hpkt.WriteScnPkt(translate(pkt), raw)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Size computes the full SCION packet size for an address pair with a given
// payload size.
func Size(local, remote *snet.UDPAddr, pldSize int) (int, error) {
	pkt, err := newEcho(local, remote, pldSize, scmp.InfoEcho{})
	if err != nil {
		return 0, err
	}
	raw := make([]byte, common.MaxMTU)
	n, err := hpkt.WriteScnPkt2(translate(pkt), raw)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// XXX(roosd): does not handle e2e or hbh extensions.
func translate(pkt *snet.Packet) *spkt.ScnPkt {
	return &spkt.ScnPkt{
		DstIA:   pkt.Destination.IA,
		SrcIA:   pkt.Source.IA,
		DstHost: pkt.Destination.Host,
		SrcHost: pkt.Source.Host,
		Path:    pkt.Path,
		L4:      pkt.L4Header,
		Pld:     pkt.Payload,
	}
}

func newEcho(local, remote *snet.UDPAddr, pldSize int, info scmp.InfoEcho) (*snet.Packet, error) {
	if remote.Path == nil && !local.IA.Equal(remote.IA) {
		return nil, serrors.New("no path for remote ISD-AS", "local", local.IA, "remote", remote.IA)
	}
	pld := make([]byte, scmp.MetaLen+info.Len()+pldSize)
	meta := scmp.Meta{InfoLen: uint8(info.Len() / common.LineLen)}
	meta.Write(pld)
	info.Write(pld[scmp.MetaLen:])

	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostFromIP(remote.Host.IP),
			},
			Source: snet.SCIONAddress{
				IA:   local.IA,
				Host: addr.HostFromIP(local.Host.IP),
			},
			Path: remote.Path,
			L4Header: scmp.NewHdr(
				scmp.ClassType{
					Class: scmp.C_General,
					Type:  scmp.T_G_EchoRequest,
				},
				len(pld),
			),
			Payload: common.RawBytes(pld),
		},
	}
	return pkt, nil
}
