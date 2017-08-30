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
// creating end-host SCION messages.
//
// Currently supports SCION/UDP and SCION/SCMP packets.
package hpkt

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// Processing/parsing callback type
type PktParser func() error

// Offsets holds start and end offsets for packet sections
type Offsets struct {
	start, end int
}

// parseCtx holds the state for the packet parser
type parseCtx struct {
	// SCION packet structure we need to fill in
	s *spkt.ScnPkt
	// Buffer to parse
	b common.RawBytes
	// Current parse offset
	offset int
	// Helper container for common header fields; also tracks the next
	// protocol we need to parse
	cmnHdr *spkt.CmnHdr

	// Memorize section start and end offsets for when we need to jump
	cmnHdrOffsets  Offsets
	extHdrOffsets  Offsets
	addrHdrOffsets Offsets
	fwdPathOffsets Offsets
	l4HdrOffsets   Offsets
	pldOffsets     Offsets

	// Methods for parsing various packet elements; can be overwritten by extensions
	// FIXME(scrye): when the need arises, these should probably be changed to queues
	// (e.g., when multiple handlers need to be chained)
	CmnHdrParser  PktParser
	HBHExtParser  PktParser
	E2EExtParser  PktParser
	AddrHdrParser PktParser
	FwdPathParser PktParser
	L4HdrParser   PktParser
	PldParser     PktParser
	ChecksumF     PktParser
}

func newParseCtx(s *spkt.ScnPkt, b common.RawBytes) *parseCtx {
	pCtx := &parseCtx{
		s:      s,
		b:      b,
		cmnHdr: &spkt.CmnHdr{}}
	pCtx.CmnHdrParser = pCtx.DefaultCmnHdrParser
	pCtx.E2EExtParser = pCtx.DefaultE2EExtParser
	pCtx.HBHExtParser = pCtx.DefaultHBHExtParser
	pCtx.AddrHdrParser = pCtx.DefaultAddrHdrParser
	pCtx.FwdPathParser = pCtx.DefaultFwdPathParser
	pCtx.L4HdrParser = pCtx.DefaultL4HdrParser
	pCtx.PldParser = pCtx.DefaultPldParser
	pCtx.ChecksumF = pCtx.DefaultChecksumF
	return pCtx
}

// ParseScnPkt populates the SCION fields in s with information from b
func ParseScnPkt(s *spkt.ScnPkt, b common.RawBytes) error {
	pCtx := newParseCtx(s, b)
	return pCtx.parse()
}

// parse contains the processing flow
func (p *parseCtx) parse() error {
	// A SCION header is parsed in the following order:
	//  1. Common header
	//  2. Extension headers, in the order they are placed in the packet.
	//  Note that extension headers can also overwrite default behavior for
	//  steps 2-6
	//  3. Address headers
	//  4. Forwarding path
	//  5. L4 header
	//  6. Payload

	if err := p.CmnHdrParser(); err != nil {
		return common.NewError("Unable to parse common header", "err", err)
	}

	// We'll advance the end offset for extensions as we parse them
	p.extHdrOffsets.start = int(p.cmnHdr.HdrLen * common.LineLen)
	p.extHdrOffsets.end = p.extHdrOffsets.start
	// Skip after SCION header
	p.offset = p.extHdrOffsets.start
ProtoLoop:
	for {
		switch p.cmnHdr.NextHdr {
		case common.HopByHopClass:
			if err := p.HBHExtParser(); err != nil {
				return common.NewError("Unable to parse extension", "err", err)
			}
		case common.End2EndClass:
			if err := p.E2EExtParser(); err != nil {
				return common.NewError("Unable to parse E2E extension", "err", err)
			}
		case common.L4SCMP:
			break ProtoLoop
		case common.L4UDP:
			break ProtoLoop
		default:
			return common.NewError("Unsupported protocol", "proto", p.cmnHdr.NextHdr)
		}
	}
	// Return to the start of the address header
	p.offset = p.cmnHdrOffsets.end
	if err := p.AddrHdrParser(); err != nil {
		return common.NewError("Unable to parse address header", "err", err)
	}
	if err := p.FwdPathParser(); err != nil {
		return common.NewError("Unable to parse path header", "err", err)
	}

	// Jump after extensions
	p.offset = p.extHdrOffsets.end
	if err := p.L4HdrParser(); err != nil {
		return common.NewError("Unable to parse L4 header", "err", err)
	}
	if err := p.PldParser(); err != nil {
		return common.NewError("Unable to parse payload header", "err", err)
	}
	if err := p.ChecksumF(); err != nil {
		return common.NewError("Checksum error", "err", err)
	}
	return nil
}

func (p *parseCtx) DefaultCmnHdrParser() error {
	p.cmnHdrOffsets.start = p.offset
	if cerr := p.cmnHdr.Parse(p.b[:spkt.CmnHdrLen]); cerr != nil {
		return cerr
	}
	p.offset += spkt.CmnHdrLen
	p.cmnHdrOffsets.end = p.offset
	return nil
}

func (p *parseCtx) DefaultHBHExtParser() error {
	if len(p.b[p.offset:]) < common.LineLen {
		return common.NewError("Truncated extension")
	}

	// Parse 3-byte extension header first
	// We know the type of the next header, so we save it for the protocol loop
	p.cmnHdr.NextHdr = common.L4ProtocolType(p.b[p.offset])
	hdrLen := p.b[p.offset+1]
	extnType := p.b[p.offset+2]

	// Parse the rest of the extension header, depending on extension type
	switch extnType {
	case common.ExtnSCMPType.Type:
		extn, cerr := scmp.ExtnFromRaw(p.b[p.offset+3:])
		if cerr != nil {
			return common.NewError("Unable to parse extension header", "err", cerr)
		}
		p.s.HBHExt = append(p.s.HBHExt, extn)
	default:
		return common.NewError("Unsupported HBH extension type", "type", extnType)
	}

	// Finished parsing another extension, advance the end offset
	p.extHdrOffsets.end += int(hdrLen * common.LineLen)
	p.offset += int(hdrLen * common.LineLen)
	return nil
}

func (p *parseCtx) DefaultE2EExtParser() error {
	return common.NewError("Not implemented")
}

func (p *parseCtx) DefaultAddrHdrParser() error {
	var cerr *common.Error
	p.addrHdrOffsets.start = p.offset
	p.s.DstIA.Parse(p.b[p.offset:])
	p.offset += addr.IABytes
	p.s.SrcIA.Parse(p.b[p.offset:])
	p.offset += addr.IABytes
	if p.s.DstHost, cerr = addr.HostFromRaw(p.b[p.offset:], p.cmnHdr.DstType); cerr != nil {
		return common.NewError("Unable to parse destination host address",
			"err", cerr)
	}
	p.offset += p.s.DstHost.Size()
	if p.s.SrcHost, cerr = addr.HostFromRaw(p.b[p.offset:], p.cmnHdr.SrcType); cerr != nil {
		return common.NewError("Unable to parse source host address",
			"err", cerr)
	}
	p.offset += p.s.SrcHost.Size()
	// Validate address padding bytes
	padBytes := util.CalcPadding(p.offset, common.LineLen)
	if pos, ok := isZeroMemory(p.b[p.offset : p.offset+padBytes]); !ok {
		return common.NewError("Invalid padding", "position", pos,
			"expected", 0, "actual", p.b[p.offset+pos])
	}
	p.offset += padBytes
	p.addrHdrOffsets.end = p.offset
	return nil
}

func (p *parseCtx) DefaultFwdPathParser() error {
	p.fwdPathOffsets.start = p.offset
	pathLen := p.cmnHdr.HdrLenBytes() - p.offset
	p.s.Path.Raw = p.b[p.offset : p.offset+pathLen]
	p.s.Path.InfOff = p.cmnHdr.InfoFOffBytes()
	p.s.Path.HopOff = p.cmnHdr.HopFOffBytes()
	p.offset += pathLen
	p.fwdPathOffsets.end = p.offset
	return nil
}

func (p *parseCtx) DefaultL4HdrParser() error {
	var cerr *common.Error
	p.l4HdrOffsets.start = p.offset

	switch p.cmnHdr.NextHdr {
	case common.L4UDP:
		if p.s.L4, cerr = l4.UDPFromRaw(p.b[p.offset : p.offset+l4.UDPLen]); cerr != nil {
			return common.NewError("Unable to parse UDP header", "err", cerr)
		}
	case common.L4SCMP:
		if p.s.L4, cerr = scmp.HdrFromRaw(p.b[p.offset : p.offset+scmp.HdrLen]); cerr != nil {
			return common.NewError("Unable to parse SCMP header", "err", cerr)
		}
	default:
		return common.NewError("Unsupported NextHdr value", "expected",
			common.L4UDP, "actual", p.cmnHdr.NextHdr)
	}

	// Enable checksum function
	p.ChecksumF = func() error {
		cerr := l4.CheckCSum(p.s.L4, p.b[p.addrHdrOffsets.start:p.addrHdrOffsets.end],
			p.b[p.pldOffsets.start:p.pldOffsets.end])
		if cerr != nil {
			return cerr
		}
		return nil
	}

	p.offset += p.s.L4.L4Len()
	p.l4HdrOffsets.end = p.offset
	return nil
}

func (p *parseCtx) DefaultPldParser() error {
	p.pldOffsets.start = p.offset
	pldLen := int(p.cmnHdr.TotalLen) - p.cmnHdr.HdrLenBytes() - p.s.L4.L4Len() -
		(p.extHdrOffsets.end - p.extHdrOffsets.start)
	if p.offset+pldLen < len(p.b) {
		return common.NewError("Incomplete packet, bad payload length",
			"expected", pldLen, "actual", len(p.b)-p.offset)
	}
	p.s.Pld = common.RawBytes(p.b[p.offset : p.offset+pldLen])
	p.offset += pldLen
	p.pldOffsets.end = p.offset
	return nil
}

func (p *parseCtx) DefaultChecksumF() error {
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
