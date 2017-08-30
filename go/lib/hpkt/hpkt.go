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

// FIXME(scrye): when SCION Conn is merged in master, move this there
func AllocScnPkt() *spkt.ScnPkt {
	return &spkt.ScnPkt{
		DstIA: &addr.ISD_AS{},
		SrcIA: &addr.ISD_AS{},
		Path:  &spath.Path{},
		// Rest of fields passed by reference
	}
}

// ParseScnPkt populates the SCION fields in s with information from b
func ParseScnPkt(s *spkt.ScnPkt, b common.RawBytes) error {
	var cerr *common.Error
	offset := 0

	cmnHdr := spkt.CmnHdr{}
	if cerr = cmnHdr.Parse(b[:spkt.CmnHdrLen]); cerr != nil {
		return cerr
	}
	offset += spkt.CmnHdrLen

	// If we find an extension, we cannot reliably parse past this point.
	// For now, only parse simple packets
	// TODO(scrye): add extension support
	if cmnHdr.NextHdr != common.L4UDP {
		return common.NewError("Unexpected protocol number", "expected",
			common.L4UDP, "actual", cmnHdr.NextHdr)
	}

	// Parse address header
	addrHdrStart := offset
	s.DstIA.Parse(b[offset:])
	offset += addr.IABytes
	s.SrcIA.Parse(b[offset:])
	offset += addr.IABytes
	if s.DstHost, cerr = addr.HostFromRaw(b[offset:], cmnHdr.DstType); cerr != nil {
		return common.NewError("Unable to parse destination host address",
			"err", cerr)
	}
	offset += s.DstHost.Size()
	if s.SrcHost, cerr = addr.HostFromRaw(b[offset:], cmnHdr.SrcType); cerr != nil {
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
	pathLen := cmnHdr.HdrLenBytes() - offset
	s.Path.Raw = b[offset : offset+pathLen]
	s.Path.InfOff = cmnHdr.InfoFOffBytes()
	s.Path.HopOff = cmnHdr.HopFOffBytes()
	offset += pathLen

	// TODO(scrye): Add extension support

	// Parse L4 header
	if cmnHdr.NextHdr != common.L4UDP {
		return common.NewError("Unsupported NextHdr value", "expected",
			common.L4UDP, "actual", cmnHdr.NextHdr)
	}
	if s.L4, cerr = l4.UDPFromRaw(b[offset : offset+l4.UDPLen]); cerr != nil {
		return common.NewError("Unable to parse UDP header", "err", cerr)
	}
	offset += s.L4.L4Len()

	// Parse payload
	pldLen := int(cmnHdr.TotalLen) - cmnHdr.HdrLenBytes() - s.L4.L4Len()
	if offset+pldLen < len(b) {
		return common.NewError("Incomplete packet, bad payload length",
			"expected", pldLen, "actual", len(b)-offset)
	}
	s.Pld = common.RawBytes(b[offset : offset+pldLen])

	// Verify checksum
	err := l4.CheckCSum(s.L4, b[addrHdrStart:addrHdrEnd],
		b[offset:offset+pldLen])
	if err != nil {
		return err
	}
	return nil
}

func WriteScnPkt(s *spkt.ScnPkt, b common.RawBytes) (int, error) {
	var cerr *common.Error
	offset := 0

	if s.L4.L4Type() != common.L4UDP {
		return 0, common.NewError("Unsupported protocol", "expected",
			common.L4UDP, "actual", s.L4.L4Type())
	}
	if s.E2EExt != nil {
		return 0, common.NewError("E2E extensions not supported", "ext", s.E2EExt)
	}
	if s.HBHExt != nil {
		return 0, common.NewError("HBH extensions not supported", "ext", s.HBHExt)
	}

	// Compute header lengths
	addrHdrLen := s.DstHost.Size() + s.SrcHost.Size() + 2*addr.IABytes
	addrPad := util.CalcPadding(addrHdrLen, common.LineLen)
	addrHdrLen += addrPad
	pathHdrLen := 0
	if s.Path != nil {
		pathHdrLen = len(s.Path.Raw)
	}
	scionHdrLen := spkt.CmnHdrLen + addrHdrLen + pathHdrLen
	pktLen := scionHdrLen + s.L4.L4Len() + s.Pld.Len()
	if len(b) < pktLen {
		return 0, common.NewError("Buffer too small", "expected", pktLen,
			"actual", len(b))
	}

	// Compute preliminary common header, but do not write it to the packet yet
	cmnHdr := spkt.CmnHdr{}
	cmnHdr.Ver = spkt.SCIONVersion
	cmnHdr.DstType = s.DstHost.Type()
	cmnHdr.SrcType = s.SrcHost.Type()
	cmnHdr.TotalLen = uint16(pktLen)
	cmnHdr.HdrLen = uint8(scionHdrLen / common.LineLen)
	cmnHdr.CurrInfoF = 0 // Updated later if necessary
	cmnHdr.CurrHopF = 0  // Updated later if necessary
	cmnHdr.NextHdr = s.L4.L4Type()
	offset += spkt.CmnHdrLen

	// Address header
	addrSlice := b[offset : offset+addrHdrLen]
	s.DstIA.Write(b[offset:])
	offset += addr.IABytes
	s.SrcIA.Write(b[offset:])
	offset += addr.IABytes
	// addr.HostAddr.Pack() is zero-copy, use it directly
	offset += copy(b[offset:], s.DstHost.Pack())
	offset += copy(b[offset:], s.SrcHost.Pack())
	// Zero memory padding
	zeroMemory(b[offset : offset+addrPad])
	offset += addrPad

	// Forwarding Path
	if s.Path != nil {
		cmnHdr.CurrInfoF = uint8((offset + s.Path.InfOff) / common.LineLen)
		cmnHdr.CurrHopF = uint8((offset + s.Path.HopOff) / common.LineLen)
		offset += copy(b[offset:], s.Path.Raw)
	}

	// Write the common header at the start of the buffer
	cmnHdr.Write(b)

	// Don't write L4 yet
	l4Slice := b[offset : offset+s.L4.L4Len()]
	offset += s.L4.L4Len()

	// Payload
	pldSlice := b[offset : offset+s.Pld.Len()]
	s.Pld.WritePld(b[offset:])
	offset += s.Pld.Len()

	// SCION/UDP Header
	cerr = l4.SetCSum(s.L4, addrSlice, pldSlice)
	if cerr != nil {
		return 0, common.NewError("Unable to compute checksum", "err", cerr)
	}
	s.L4.Write(l4Slice)

	return offset, nil
}

func isZeroMemory(b common.RawBytes) (int, bool) {
	for i := range b {
		if b[i] != 0 {
			return i, false
		}
	}
	return 0, true
}

func zeroMemory(b common.RawBytes) {
	for i := range b {
		b[i] = 0
	}
}
