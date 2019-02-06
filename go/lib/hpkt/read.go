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
	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
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
	AddrHdrParser pktParser
	FwdPathParser pktParser
	L4Parser      pktParser
}

func newParseCtx(s *spkt.ScnPkt, b common.RawBytes) *parseCtx {
	pCtx := &parseCtx{
		s:      s,
		b:      b,
		cmnHdr: &spkt.CmnHdr{},
	}
	pCtx.AddrHdrParser = pCtx.DefaultAddrHdrParser
	pCtx.FwdPathParser = pCtx.DefaultFwdPathParser
	pCtx.L4Parser = pCtx.DefaultL4Parser
	return pCtx
}

// parse contains the processing flow
func (p *parseCtx) parse() error {
	var err error

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
		return common.NewBasicError("Unable to parse common header", err)
	}
	p.nextHdr = p.cmnHdr.NextHdr

	// Skip after SCION header
	p.offset = int(p.cmnHdr.HdrLen * common.LineLen)

	p.s.HBHExt, p.s.E2EExt, err = p.parseExtensions()
	if err != nil {
		return err
	}
	p.extHdrOffsets.end = p.offset

	// Return to the start of the address header
	p.offset = p.cmnHdrOffsets.end
	if err := p.AddrHdrParser(); err != nil {
		return common.NewBasicError("Unable to parse address header", err)
	}
	if err := p.FwdPathParser(); err != nil {
		return common.NewBasicError("Unable to parse path header", err)
	}

	// Jump after extensions
	p.offset = p.extHdrOffsets.end
	if err := p.L4Parser(); err != nil {
		return common.NewBasicError("Unable to parse L4 content", err)
	}
	return nil
}

func (p *parseCtx) parseExtensions() ([]common.Extension, []common.Extension, error) {
	var extns []common.Extension
	for p.nextHdr == common.HopByHopClass || p.nextHdr == common.End2EndClass {
		var extn layers.Extension
		err := extn.DecodeFromBytes(p.b[p.offset:], gopacket.NilDecodeFeedback)
		if err != nil {
			return nil, nil, common.NewBasicError("Unable to parse extensions", err)
		}

		extnData, err := layers.ExtensionFactory(p.nextHdr, &extn)
		if err != nil {
			return nil, nil, err
		}
		extns = append(extns, extnData)

		p.nextHdr = extn.NextHeader
		p.offset += len(extn.Contents)
	}
	return ValidateExtensions(extns)
}

func (p *parseCtx) CmnHdrParser() error {
	p.cmnHdrOffsets.start = p.offset
	if err := p.cmnHdr.Parse(p.b[:spkt.CmnHdrLen]); err != nil {
		return err
	}
	p.offset += spkt.CmnHdrLen
	p.cmnHdrOffsets.end = p.offset

	if int(p.cmnHdr.TotalLen) != len(p.b) {
		return common.NewBasicError("Malformed total packet length", nil,
			"expected", p.cmnHdr.TotalLen, "actual", len(p.b))
	}
	return nil
}

func (p *parseCtx) DefaultAddrHdrParser() error {
	var err error
	p.addrHdrOffsets.start = p.offset
	p.s.DstIA.Parse(p.b[p.offset:])
	p.offset += addr.IABytes
	p.s.SrcIA.Parse(p.b[p.offset:])
	p.offset += addr.IABytes
	if p.s.DstHost, err = addr.HostFromRaw(p.b[p.offset:], p.cmnHdr.DstType); err != nil {
		return common.NewBasicError("Unable to parse destination host address", err)
	}
	p.offset += p.s.DstHost.Size()
	if p.s.SrcHost, err = addr.HostFromRaw(p.b[p.offset:], p.cmnHdr.SrcType); err != nil {
		return common.NewBasicError("Unable to parse source host address", err)
	}
	p.offset += p.s.SrcHost.Size()
	// Validate address padding bytes
	padBytes := util.CalcPadding(p.offset, common.LineLen)
	if pos, ok := isZeroMemory(p.b[p.offset : p.offset+padBytes]); !ok {
		return common.NewBasicError("Invalid padding", nil,
			"position", pos, "expected", 0, "actual", p.b[p.offset+pos])
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
			return common.NewBasicError("Unable to parse UDP header", err)
		}
	case common.L4SCMP:
		if p.s.L4, err = scmp.HdrFromRaw(p.b[p.offset : p.offset+scmp.HdrLen]); err != nil {
			return common.NewBasicError("Unable to parse SCMP header", err)
		}
	default:
		return common.NewBasicError("Unsupported NextHdr value", nil,
			"expected", common.L4UDP, "actual", p.nextHdr)
	}
	p.offset += p.s.L4.L4Len()
	p.l4HdrOffsets.end = p.offset

	// Parse L4 payload
	p.pldOffsets.start = p.offset
	pldLen := len(p.b) - p.pldOffsets.start
	if err = p.s.L4.Validate(pldLen); err != nil {
		return common.NewBasicError("L4 validation failed", err)
	}
	switch p.nextHdr {
	case common.L4UDP:
		p.s.Pld = common.RawBytes(p.b[p.offset : p.offset+pldLen])
	case common.L4SCMP:
		hdr, ok := p.s.L4.(*scmp.Hdr)
		if !ok {
			return common.NewBasicError(
				"Unable to extract SCMP payload, type assertion failed", nil)
		}
		p.s.Pld, err = scmp.PldFromRaw(p.b[p.offset:p.offset+pldLen],
			scmp.ClassType{Class: hdr.Class, Type: hdr.Type})
		if err != nil {
			return common.NewBasicError("Unable to parse SCMP payload", err)
		}
	}
	p.offset += pldLen
	p.pldOffsets.end = p.offset

	// Run checksum function
	err = l4.CheckCSum(p.s.L4, p.b[p.addrHdrOffsets.start:p.addrHdrOffsets.end],
		p.b[p.pldOffsets.start:p.pldOffsets.end])
	if err != nil {
		return common.NewBasicError("Checksum failed", err)
	}
	return nil
}
