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
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
)

type SCMPDummy struct {
	layers.BaseLayer
	// TODO(shitz): Move scmp.Hdr here.
	scmp.Hdr
	// TODO(shitz): Make this an actual payload
	Payload []byte

	scn *SCION
}

func (s *SCMPDummy) LayerType() gopacket.LayerType {
	return LayerTypeSCMP
}

func (s *SCMPDummy) CanDecode() gopacket.LayerClass {
	return LayerTypeSCMP
}

func (s *SCMPDummy) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (s *SCMPDummy) LayerPayload() []byte {
	return s.Payload
}

func (s *SCMPDummy) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if opts.FixLengths {
		s.TotalLen = uint16(scmp.HdrLen + len(s.Payload))
	}
	buf, err := b.PrependBytes(int(s.TotalLen))
	if err != nil {
		return err
	}
	copy(buf[scmp.HdrLen:], s.Payload)

	if opts.ComputeChecksums {
		rawAddrHdr := make([]byte, s.scn.AddrHdrLen())
		if err := s.scn.SerializeAddrHdr(rawAddrHdr); err != nil {
			return err
		}
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

func (s *SCMPDummy) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < scmp.HdrLen {
		df.SetTruncated()
		return serrors.New("packet data is shorter than SCMP header length", "min", scmp.HdrLen,
			"actual", len(data))
	}
	h, err := scmp.HdrFromRaw(data)
	if err != nil {
		return err
	}
	if int(h.TotalLen) > len(data) {
		df.SetTruncated()
		return serrors.New("packet data missing", "expected", h.TotalLen, "actual", len(data))
	}
	s.Hdr = *h
	s.Contents = data[:scmp.HdrLen]
	s.Payload = data[scmp.HdrLen:]
	return nil
}

func (s *SCMPDummy) String() string {
	return fmt.Sprintf("%s\nPayload: %s", &s.Hdr, s.Payload)
}

func (s *SCMPDummy) SetNetworkLayerForChecksum(l gopacket.NetworkLayer) error {
	s.scn = l.(*SCION)
	return nil
}

func decodeSCMPDummy(data []byte, pb gopacket.PacketBuilder) error {
	scmp := &SCMP{}
	err := scmp.DecodeFromBytes(data, pb)
	pb.AddLayer(scmp)
	if err != nil {
		return err
	}
	return nil
}
