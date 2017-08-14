// Copyright 2016 ETH Zurich
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

package spkt

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// SCION Packet structure.
type ScnPkt struct {
	CmnHdr  *CmnHdr
	DstIA   *addr.ISD_AS
	SrcIA   *addr.ISD_AS
	DstHost addr.HostAddr
	SrcHost addr.HostAddr
	Path    *spath.Path
	HBHExt  []common.Extension
	E2EExt  []common.Extension
	L4      l4.L4Header
	Pld     common.Payload
}

func ScnPktFromRaw(b common.RawBytes) (*ScnPkt, error) {
	s := &ScnPkt{}
	if err := s.Parse(b); err != nil {
		return nil, err
	}
	return s, nil
}

func NewScnPkt() *ScnPkt {
	return &ScnPkt{
		CmnHdr: &CmnHdr{},
		DstIA:  &addr.ISD_AS{},
		SrcIA:  &addr.ISD_AS{},
		Path:   &spath.Path{},
		// Rest of fields passed by reference
	}
}

func (s *ScnPkt) Parse(b common.RawBytes) error {
	var cerr *common.Error
	offset := 0

	// Parse common header
	if cerr = s.CmnHdr.Parse(b[:CmnHdrLen]); cerr != nil {
		return cerr
	}
	offset += CmnHdrLen

	// Parse address header
	s.DstIA.Parse(b[offset:])
	offset += addr.IABytes
	s.SrcIA.Parse(b[offset:])
	offset += addr.IABytes
	if s.DstHost, cerr = addr.HostFromRaw(b[offset:], s.CmnHdr.DstType); cerr != nil {
		return common.NewError("Unable to parse destination host address",
			"err", cerr)
	}
	offset += s.DstHost.Size()
	if s.SrcHost, cerr = addr.HostFromRaw(b[offset:], s.CmnHdr.SrcType); cerr != nil {
		return common.NewError("Unable to parse source host address",
			"err", cerr)
	}
	offset += s.SrcHost.Size()

	// Validate address padding bytes
	addrHdrLen := 2*addr.IABytes + s.DstHost.Size() + s.SrcHost.Size()
	padBytes := util.CalcPadding(addrHdrLen, common.LineLen)
	if pos, ok := isZeroMemory(b[offset : offset+padBytes]); !ok {
		return common.NewError("Invalid padding", "position", pos,
			"expected", 0, "actual", b[offset+pos])
	}
	offset += padBytes
	addrHdrLen += padBytes

	// Parse path header
	pathLen := s.CmnHdr.HdrLenBytes() - CmnHdrLen - addrHdrLen
	s.Path.Raw = b[offset : offset+pathLen]
	s.Path.InfOff = s.CmnHdr.InfoFOffBytes()
	s.Path.HopOff = s.CmnHdr.HopFOffBytes()
	offset += pathLen

	// TODO(scrye): Add extension support

	// Parse L4 header
	if s.CmnHdr.NextHdr != common.L4UDP {
		return common.NewError("Unsupported NextHdr value", "expected",
			common.L4UDP, "actual", s.CmnHdr.NextHdr)
	}
	if s.L4, cerr = l4.UDPFromRaw(b[offset : offset+l4.UDPLen]); cerr != nil {
		return common.NewError("Unable to parse UDP header", "err", cerr)
	}
	offset += s.L4.L4Len()

	// Parse payload
	pldLen := int(s.CmnHdr.TotalLen) - s.CmnHdr.HdrLenBytes() - s.L4.L4Len()
	if offset+pldLen < len(b) {
		return common.NewError("Incomplete packet, bad payload length",
			"expected", pldLen, "actual", len(b)-offset)
	}
	s.Pld = common.RawBytes(b[offset:])
	return nil
}

func (s *ScnPkt) Copy() *ScnPkt {
	c := &ScnPkt{}
	if s.DstIA != nil {
		c.DstIA = s.DstIA.Copy()
	}
	if s.SrcIA != nil {
		c.SrcIA = s.SrcIA.Copy()
	}
	if s.DstHost != nil {
		c.DstHost = s.DstHost.Copy()
	}
	if s.SrcHost != nil {
		c.SrcHost = s.SrcHost.Copy()
	}
	if s.Path != nil {
		c.Path = s.Path.Copy()
	}
	for _, e := range s.HBHExt {
		c.HBHExt = append(c.HBHExt, e.Copy())
	}
	for _, e := range s.E2EExt {
		c.E2EExt = append(c.E2EExt, e.Copy())
	}
	if s.L4 != nil {
		c.L4 = s.L4.Copy()
	}
	// TODO(kormat): define payload interface, with Copy()
	return c
}

func (s *ScnPkt) Reverse() *common.Error {
	s.DstIA, s.SrcIA = s.SrcIA, s.DstIA
	s.DstHost, s.SrcHost = s.SrcHost, s.DstHost
	if s.Path != nil {
		if err := s.Path.Reverse(); err != nil {
			return err
		}
	}
	// FIXME(kormat): handle reversing extensions
	if s.L4 != nil {
		s.L4.Reverse()
	}
	return nil
}

func (s *ScnPkt) AddrLen() int {
	addrLen := addr.IABytes*2 + s.DstHost.Size() + s.SrcHost.Size()
	return addrLen + util.CalcPadding(addrLen, common.LineLen)
}

// HdrLen returns the length of the header, in bytes.
func (s *ScnPkt) HdrLen() int {
	l := CmnHdrLen + s.AddrLen()
	if s.Path != nil {
		l += len(s.Path.Raw)
	}
	return l
}

func (s *ScnPkt) TotalLen() int {
	l := s.HdrLen()
	for _, h := range s.HBHExt {
		l += h.Len() + common.ExtnSubHdrLen
	}
	for _, e := range s.E2EExt {
		l += e.Len() + common.ExtnSubHdrLen
	}
	if s.L4 != nil {
		l += s.L4.L4Len()
	}
	if s.Pld != nil {
		l += s.Pld.Len()
	}
	return l
}

func isZeroMemory(b common.RawBytes) (int, bool) {
	for i := range b {
		if b[i] != 0 {
			return i, false
		}
	}
	return 0, true
}
