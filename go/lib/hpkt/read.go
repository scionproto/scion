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

package hpkt

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// ParseScnPkt populates the SCION fields in s with information from b
func ParseScnPkt(s *spkt.ScnPkt, b common.RawBytes) error {
	pCtx := newParseCtx(s, b)
	return pCtx.parse()
}

// offsets holds start and end offsets for packet sections
type offsets struct {
	start, end int
}

// Processing/parsing callback type
type pktParser func() error

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
	// Number of found HBH extensions
	hbhCounter int
	// Maximum number of allowed HBH extensions
	hbhLimit int
	// Protocol type of next header (L4, HBH class, E2E class)
	nextHdr common.L4ProtocolType

	// Memorize section start and end offsets for when we need to jump
	cmnHdrOffsets  offsets
	extHdrOffsets  offsets
	addrHdrOffsets offsets
	fwdPathOffsets offsets
	l4HdrOffsets   offsets
	pldOffsets     offsets

	// Methods for parsing various packet elements; can be overwritten by extensions
	// FIXME(scrye): when the need arises, these should probably be changed to queues
	// (e.g., when multiple handlers need to be chained)
	HBHExtParser  pktParser
	E2EExtParser  pktParser
	AddrHdrParser pktParser
	FwdPathParser pktParser
	L4Parser      pktParser
}

func newParseCtx(s *spkt.ScnPkt, b common.RawBytes) *parseCtx {
	pCtx := &parseCtx{
		s:        s,
		b:        b,
		cmnHdr:   &spkt.CmnHdr{},
		hbhLimit: common.ExtnMaxHBH,
	}
	pCtx.E2EExtParser = pCtx.DefaultE2EExtParser
	pCtx.HBHExtParser = pCtx.DefaultHBHExtParser
	pCtx.AddrHdrParser = pCtx.DefaultAddrHdrParser
	pCtx.FwdPathParser = pCtx.DefaultFwdPathParser
	pCtx.L4Parser = pCtx.DefaultL4Parser
	return pCtx
}

// parse contains the processing flow
func (p *parseCtx) parse() error {
	// A SCION header is parsed in the following order:
	//  1. Common header
	//  2. Extension headers, in the order they are placed in the packet.
	//  3. Address headers
	//  4. Forwarding path
	//  5. L4 header
	//  6. Payload
	//
	// Hop By Hop (HBH) extensions can override 2-6, while End to end (E2E)
	// extensions can override 5-6.

	if err := p.CmnHdrParser(); err != nil {
		return common.NewCError("Unable to parse common header", "err", err)
	}
	p.nextHdr = p.cmnHdr.NextHdr

	// We'll advance the end offset for extensions as we parse them
	p.extHdrOffsets.start = int(p.cmnHdr.HdrLen * common.LineLen)
	p.extHdrOffsets.end = p.extHdrOffsets.start
	// Skip after SCION header
	p.offset = p.extHdrOffsets.start

	if err := p.HBHAllExtsParser(); err != nil {
		return common.NewCError("Unable to parse HBH extensions", "err", err)
	}

	if err := p.E2EAllExtsParser(); err != nil {
		return common.NewCError("Unable to parse E2E extensions", "err", err)
	}

	// Return to the start of the address header
	p.offset = p.cmnHdrOffsets.end
	if err := p.AddrHdrParser(); err != nil {
		return common.NewCError("Unable to parse address header", "err", err)
	}
	if err := p.FwdPathParser(); err != nil {
		return common.NewCError("Unable to parse path header", "err", err)
	}

	// Jump after extensions
	p.offset = p.extHdrOffsets.end
	if err := p.L4Parser(); err != nil {
		return common.NewCError("Unable to parse L4 content", "err", err)
	}
	return nil
}

func (p *parseCtx) CmnHdrParser() error {
	p.cmnHdrOffsets.start = p.offset
	if err := p.cmnHdr.Parse(p.b[:spkt.CmnHdrLen]); err != nil {
		return err
	}
	p.offset += spkt.CmnHdrLen
	p.cmnHdrOffsets.end = p.offset

	if int(p.cmnHdr.TotalLen) != len(p.b) {
		return common.NewCError("Malformed total packet length", "expected", p.cmnHdr.TotalLen,
			"actual", len(p.b))
	}
	return nil
}

func (p *parseCtx) HBHAllExtsParser() error {
	// SCION packets can contain at most 3 HBH extensions, which must appear
	// immediately after the path header. If an SCMP HBH extension is present,
	// it must be the first extension and raises the allowed HBH limit to 4.
	// E2E extensions appear after HBH extensions (if any), or after the path
	// header.
	for p.nextHdr == common.HopByHopClass {
		p.hbhCounter += 1
		if err := p.HBHExtParser(); err != nil {
			return common.NewCError("Unable to parse HBH extension", "err", err)
		}
		if p.hbhCounter > p.hbhLimit {
			ext := p.s.HBHExt[len(p.s.HBHExt)-1]
			return common.NewCError("HBH extension limit exceeded", "type", ext.Class(),
				"position", p.hbhCounter-1, "limit", p.hbhLimit)
		}
	}
	return nil
}

func (p *parseCtx) E2EAllExtsParser() error {
	for p.nextHdr == common.End2EndClass {
		if err := p.E2EExtParser(); err != nil {
			return common.NewCError("Unable to parse E2E extension", "err", err)
		}
	}
	return nil
}

func (p *parseCtx) DefaultHBHExtParser() error {
	if len(p.b[p.offset:]) < common.LineLen {
		return common.NewCError("Truncated extension")
	}

	// Parse 3-byte extension header first
	// We know the type of the next header, so we save it for the protocol loop
	p.nextHdr = common.L4ProtocolType(p.b[p.offset])
	hdrLen := p.b[p.offset+1]
	extnType := p.b[p.offset+2]
	// Advance end of extensions headers offset
	p.extHdrOffsets.end += int(hdrLen * common.LineLen)

	// Parse the rest of the extension header, depending on extension type
	switch extnType {
	case common.ExtnSCMPType.Type:
		if p.hbhCounter != 1 {
			// SCMP HBH extensions must come immediately after the path header
			return common.NewCError("Invalid placement of HBH SCMP extension (must be first)",
				"position", p.hbhCounter-1, "offset", p.offset)
		}
		// SCMP HBH extensions increase the limit of HBH extensions by 1
		p.hbhLimit += 1

		extn, err := scmp.ExtnFromRaw(p.b[p.offset+common.ExtnSubHdrLen : p.extHdrOffsets.end])
		if err != nil {
			return common.NewCError("Unable to parse extension header", "type", extn.Class(),
				"position", p.hbhCounter-1, "err", err)
		}
		p.s.HBHExt = append(p.s.HBHExt, extn)
	default:
		return common.NewCError("Unsupported HBH extension type", "type", extnType,
			"position", p.hbhCounter-1)
	}

	p.offset = p.extHdrOffsets.end
	return nil
}

func (p *parseCtx) DefaultE2EExtParser() error {
	return common.NewCError("Not implemented")
}

func (p *parseCtx) DefaultAddrHdrParser() error {
	var err error
	p.addrHdrOffsets.start = p.offset
	p.s.DstIA.Parse(p.b[p.offset:])
	p.offset += addr.IABytes
	p.s.SrcIA.Parse(p.b[p.offset:])
	p.offset += addr.IABytes
	if p.s.DstHost, err = addr.HostFromRaw(p.b[p.offset:], p.cmnHdr.DstType); err != nil {
		return common.NewCError("Unable to parse destination host address",
			"err", err)
	}
	p.offset += p.s.DstHost.Size()
	if p.s.SrcHost, err = addr.HostFromRaw(p.b[p.offset:], p.cmnHdr.SrcType); err != nil {
		return common.NewCError("Unable to parse source host address",
			"err", err)
	}
	p.offset += p.s.SrcHost.Size()
	// Validate address padding bytes
	padBytes := util.CalcPadding(p.offset, common.LineLen)
	if pos, ok := isZeroMemory(p.b[p.offset : p.offset+padBytes]); !ok {
		return common.NewCError("Invalid padding", "position", pos,
			"expected", 0, "actual", p.b[p.offset+pos])
	}
	p.offset += padBytes
	p.addrHdrOffsets.end = p.offset
	return nil
}

func (p *parseCtx) DefaultFwdPathParser() error {
	p.fwdPathOffsets.start = p.offset
	pathLen := p.cmnHdr.HdrLenBytes() - p.offset
	if pathLen > 0 {
		if p.s.Path == nil {
			p.s.Path = &spath.Path{}
		}
		p.s.Path.Raw = p.b[p.offset : p.offset+pathLen]
		p.s.Path.InfOff = p.cmnHdr.InfoFOffBytes() - p.offset
		p.s.Path.HopOff = p.cmnHdr.HopFOffBytes() - p.offset
		p.offset += pathLen
	}
	p.fwdPathOffsets.end = p.offset
	return nil
}

func (p *parseCtx) DefaultL4Parser() error {
	var err error
	p.l4HdrOffsets.start = p.offset

	switch p.nextHdr {
	case common.L4UDP:
		if p.s.L4, err = l4.UDPFromRaw(p.b[p.offset : p.offset+l4.UDPLen]); err != nil {
			return common.NewCError("Unable to parse UDP header", "err", err)
		}
	case common.L4SCMP:
		if p.s.L4, err = scmp.HdrFromRaw(p.b[p.offset : p.offset+scmp.HdrLen]); err != nil {
			return common.NewCError("Unable to parse SCMP header", "err", err)
		}
	default:
		return common.NewCError("Unsupported NextHdr value", "expected",
			common.L4UDP, "actual", p.nextHdr)
	}
	p.offset += p.s.L4.L4Len()
	p.l4HdrOffsets.end = p.offset

	// Parse L4 payload
	p.pldOffsets.start = p.offset
	pldLen := len(p.b) - p.pldOffsets.start
	if err = p.s.L4.Validate(pldLen); err != nil {
		return common.NewCError("L4 validation failed", "err", err)
	}
	switch p.nextHdr {
	case common.L4UDP:
		p.s.Pld = common.RawBytes(p.b[p.offset : p.offset+pldLen])
	case common.L4SCMP:
		hdr, ok := p.s.L4.(*scmp.Hdr)
		if !ok {
			return common.NewCError("Unable to extract SCMP payload, type assertion failed.")
		}
		p.s.Pld, err = scmp.PldFromRaw(p.b[p.offset:p.offset+pldLen],
			scmp.ClassType{Class: hdr.Class, Type: hdr.Type})
		if err != nil {
			return common.NewCError("Unable to parse SCMP payload", "err", err)
		}
	}
	p.offset += pldLen
	p.pldOffsets.end = p.offset

	// Run checksum function
	err = l4.CheckCSum(p.s.L4, p.b[p.addrHdrOffsets.start:p.addrHdrOffsets.end],
		p.b[p.pldOffsets.start:p.pldOffsets.end])
	if err != nil {
		return common.NewCError("Checksum failed", "err", err)
	}
	return nil
}
