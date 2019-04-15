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
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
)

// This type alias is to avoid name clash with Payload field in layers.BaseLayer
type Pld = scmp.Payload

type SCMP struct {
	layers.BaseLayer
	scmp.Hdr
	*Pld
	scn *Scion
}

var LayerTypeSCMP = gopacket.RegisterLayerType(
	1361,
	gopacket.LayerTypeMetadata{
		Name:    "SCMP",
		Decoder: gopacket.DecodeFunc(decodeSCMP),
	},
)

func (s *SCMP) LayerType() gopacket.LayerType {
	return LayerTypeSCMP
}

func (s *SCMP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if opts.FixLengths {
		s.TotalLen = uint16(scmp.HdrLen + s.Pld.Len())
	}
	buf, err := b.PrependBytes(int(s.TotalLen))
	if err != nil {
		return err
	}
	if _, err := s.WritePld(buf[scmp.HdrLen:]); err != nil {
		return err
	}
	if opts.ComputeChecksums {
		rawAddrHdr := make(common.RawBytes, s.scn.AddrHdr.Len())
		s.scn.AddrHdr.Write(rawAddrHdr)
		s.Checksum, err = l4.CalcCSum(&s.Hdr, rawAddrHdr, buf[scmp.HdrLen:])
		if err != nil {
			return err
		}
		s.Checksum, err = l4.CalcCSum(&s.Hdr, rawAddrHdr, buf[scmp.HdrLen:])
		if err != nil {
			return err
		}
	}
	if err := s.Hdr.Write(buf); err != nil {
		return err
	}
	return nil
}

func (s *SCMP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < scmp.HdrLen {
		df.SetTruncated()
		return fmt.Errorf("Invalid SCMP header. Length %d less than %d",
			len(data), scmp.HdrLen)
	}
	h, err := scmp.HdrFromRaw(data)
	if err != nil {
		return err
	}
	if int(h.TotalLen) > len(data) {
		df.SetTruncated()
		h.TotalLen = uint16(len(data))
	}
	s.Hdr = *h
	s.Contents = data[:scmp.HdrLen]
	s.Payload = data[scmp.HdrLen:]
	p, err := scmp.PldFromRaw(s.Payload, scmp.ClassType{Class: s.Class, Type: s.Type})
	if err != nil {
		return err
	}
	s.Pld = p
	return nil
}

// Strings is a pretty print of the quotes, trying to display pretty-printed quotes if they parse
// without errors, otherwise display hex of the slice
func (s *SCMP) String() string {
	var str []string
	str = append(str, fmt.Sprintf("%s", &s.Hdr))
	if s.Meta != nil {
		str = append(str, fmt.Sprintf("Meta={ %s }", s.Meta))
	}
	if s.Info != nil {
		str = append(str, fmt.Sprintf("Info={ %s }", s.Info))
	}
	var cmn *spkt.CmnHdr
	if len(s.CmnHdr) > 0 {
		var err error
		if cmn, err = spkt.CmnHdrFromRaw(s.CmnHdr); err != nil {
			str = append(str, fmt.Sprintf("CmnHdr=%s", s.CmnHdr))
		} else {
			str = append(str, fmt.Sprintf("CmnHdr={ %s }", cmn))
		}
	}
	if len(s.AddrHdr) > 0 && cmn != nil {
		if addr, err := ParseRawAddrHdr(s.AddrHdr, cmn.SrcType, cmn.DstType); err != nil {
			str = append(str, fmt.Sprintf("AddrHdr=%s", s.AddrHdr))
		} else {
			str = append(str, fmt.Sprintf("AddrHdr={ %s }", addr))
		}
	}
	if len(s.PathHdr) > 0 {
		path := &ScnPath{}
		if err := path.Parse(s.PathHdr); err != nil {
			str = append(str, fmt.Sprintf("PathHdr=%s", s.PathHdr))
		} else {
			str = append(str, fmt.Sprintf("PathHdr={ %s }", path))
		}
	}
	if len(s.ExtHdrs) > 0 {
		str = append(str, fmt.Sprintf("ExtHdrs=%s", s.ExtHdrs))
	}
	if len(s.L4Hdr) > 0 {
		switch s.Meta.L4Proto {
		case common.L4UDP:
			if udp, err := l4.UDPFromRaw(s.L4Hdr); err != nil {
				str = append(str, fmt.Sprintf("L4Hdr=%s", s.L4Hdr))
			} else {
				str = append(str, fmt.Sprintf("L4Hdr={ %s }", udp))
			}
		case common.L4SCMP:
			if hdr, err := scmp.HdrFromRaw(s.L4Hdr); err != nil {
				str = append(str, fmt.Sprintf("L4Hdr=%s", s.L4Hdr))
			} else {
				str = append(str, fmt.Sprintf("L4Hdr={ %s }", hdr))
			}
		default:
			str = append(str, fmt.Sprintf("L4Hdr=%s", s.L4Hdr))
		}
	}
	return strings.Join(str, " ")
}

func (s *SCMP) SetNetworkLayerForChecksum(l gopacket.NetworkLayer) error {
	s.scn = l.(*Scion)
	return nil
}

func decodeSCMP(data []byte, p gopacket.PacketBuilder) error {
	s := &SCMP{}
	err := s.DecodeFromBytes(data, p)
	p.AddLayer(s)
	if err != nil {
		return err
	}
	return nil
}
