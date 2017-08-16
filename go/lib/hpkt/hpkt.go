// Copyright 2017 ETH Zurich
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

// Package hpkt (Host Packet) contains low level primitives for parsing and
// creating end-host SCION messages
package hpkt

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

func AllocScnPkt() *spkt.ScnPkt {
	return &spkt.ScnPkt{
		CmnHdr: &spkt.CmnHdr{},
		DstIA:  &addr.ISD_AS{},
		SrcIA:  &addr.ISD_AS{},
		Path:   &spath.Path{},
		// Rest of fields passed by reference
	}
}

// ParseScnPkt populates the SCION fields in s with information from b
func ParseScnPkt(s *spkt.ScnPkt, b common.RawBytes) error {
	var cerr *common.Error
	offset := 0

	// Parse common header
	if cerr = s.CmnHdr.Parse(b[:spkt.CmnHdrLen]); cerr != nil {
		return cerr
	}
	offset += spkt.CmnHdrLen

	// If we find an extension, we cannot reliably parse past this point.
	// For now, only parse simple packets
	// TODO(scrye): add extension support
	if s.CmnHdr.NextHdr != common.L4UDP {
		return common.NewError("Unexpected protocol number", "expected",
			common.L4UDP, "actual", s.CmnHdr.NextHdr)
	}

	// Parse address header
	addrHdrStart := offset
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
	padBytes := util.CalcPadding(offset, common.LineLen)
	if pos, ok := isZeroMemory(b[offset : offset+padBytes]); !ok {
		return common.NewError("Invalid padding", "position", pos,
			"expected", 0, "actual", b[offset+pos])
	}
	offset += padBytes
	addrHdrEnd := offset

	// Parse path header
	pathLen := s.CmnHdr.HdrLenBytes() - offset
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
	s.Pld = common.RawBytes(b[offset : offset+pldLen])

	// Verify checksum
	err := l4.CheckCSum(s.L4, b[addrHdrStart:addrHdrEnd],
		b[offset:offset+pldLen])
	if err != nil {
		return common.NewError("Bad checksum", "err", err)
	}
	return nil
}

func isZeroMemory(b common.RawBytes) (int, bool) {
	for i := range b {
		if b[i] != 0 {
			return i, false
		}
	}
	return 0, true
}
