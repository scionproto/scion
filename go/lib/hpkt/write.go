// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

func WriteScnPkt(s *spkt.ScnPkt, b common.RawBytes) (int, error) {
	var err error
	var lastNextHdr *uint8
	offset := 0

	if s.E2EExt != nil {
		return 0, common.NewBasicError("E2E extensions not supported", nil, "ext", s.E2EExt)
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
		return 0, common.NewBasicError("Buffer too small", nil,
			"expected", pktLen, "actual", len(b))
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
	if !s.Path.IsEmpty() {
		cmnHdr.CurrInfoF = uint8((offset + s.Path.InfOff) / common.LineLen)
		cmnHdr.CurrHopF = uint8((offset + s.Path.HopOff) / common.LineLen)
		offset += copy(b[offset:], s.Path.Raw)
	}
	// HBH extensions
	if len(s.HBHExt) > 0 {
		l, nh, err := writeScnPktExtn(s, b[offset:])
		if err != nil {
			return 0, err
		}
		lastNextHdr = nh
		*lastNextHdr = uint8(cmnHdr.NextHdr)
		cmnHdr.NextHdr = common.HopByHopClass
		cmnHdr.TotalLen += uint16(l)
		offset += l
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

	// SCION/L4 Header
	s.L4.SetPldLen(s.Pld.Len())
	err = l4.SetCSum(s.L4, addrSlice, pldSlice)
	if err != nil {
		return 0, common.NewBasicError("Unable to compute checksum", err)
	}
	s.L4.Write(l4Slice)

	return offset, nil
}

func writeScnPktExtn(s *spkt.ScnPkt, b common.RawBytes) (int, *uint8, error) {
	var extHdrLen, offset int
	max := 3
	l4Type := s.L4.L4Type()
	for i, ext := range s.HBHExt {
		if ext.Type() == common.ExtnSCMPType {
			if i != 0 {
				// This also triggers if there are multiple SCMP extensions
				return 0, nil, common.NewBasicError("HBH SCMP extension has to be the first one",
					nil, "index", i)
			}
			if l4Type != common.L4SCMP {
				return 0, nil, common.NewBasicError("HBH SCMP extension for a non SCMP packet",
					nil, "ext", s.HBHExt)
			}
			max += 1
		}
		if i > max {
			return 0, nil, common.NewBasicError("Too many HBH extensions",
				nil, "max", max, "actual", i)
		}
		// Set all nextHdr fields as HBH, later we update last extension and common header
		b[offset] = uint8(common.HopByHopClass)
		extHdrLen = common.ExtnSubHdrLen + ext.Len()
		b[offset+1] = uint8(extHdrLen / common.LineLen)
		b[offset+2] = ext.Type().Type
		ext.Write(b[offset+common.ExtnSubHdrLen:])
		offset += extHdrLen
	}
	return offset, &b[offset-extHdrLen], nil
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
