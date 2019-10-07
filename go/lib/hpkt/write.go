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
	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

func WriteScnPkt(s *spkt.ScnPkt, b common.RawBytes) (int, error) {
	var err error
	offset := 0

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

	buffer := gopacket.NewSerializeBuffer()
	switch s.L4.L4Type() {
	case common.L4UDP:
		buffer.PushLayer(layers.LayerTypeSCIONUDP)
	case common.L4SCMP:
		buffer.PushLayer(layers.LayerTypeSCMP)
	default:
		return 0, common.NewBasicError("Unsupported L4", nil, "type", s.L4.L4Type())
	}
	if err := writeExtensionHeaders(s, buffer); err != nil {
		return 0, err
	}
	bytes := buffer.Bytes()
	offset += copy(b[offset:], bytes)
	cmnHdr.NextHdr, err = getNextHeaderType(buffer)
	if err != nil {
		return 0, err
	}
	cmnHdr.TotalLen += uint16(len(bytes))

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

func writeExtensionHeaders(s *spkt.ScnPkt, buffer gopacket.SerializeBuffer) error {
	if err := writeExtensions(s.E2EExt, buffer); err != nil {
		return err
	}
	return writeExtensions(s.HBHExt, buffer)
}

func writeExtensions(extensions []common.Extension, buffer gopacket.SerializeBuffer) error {
	for i := len(extensions) - 1; i >= 0; i-- {
		nextHeaderType, err := getNextHeaderType(buffer)
		if err != nil {
			return err
		}
		extn, err := layers.ExtensionDataToExtensionLayer(nextHeaderType, extensions[i])
		if err != nil {
			return err
		}
		err = extn.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true})
		if err != nil {
			return err
		}
		switch extensions[i].Class() {
		case common.HopByHopClass:
			buffer.PushLayer(layers.LayerTypeHopByHopExtension)
		case common.End2EndClass:
			buffer.PushLayer(layers.LayerTypeEndToEndExtension)
		default:
			return serrors.New("cannot push unknown layer")
		}
	}
	return nil
}

func getNextHeaderType(buffer gopacket.SerializeBuffer) (common.L4ProtocolType, error) {
	serializedLayers := buffer.Layers()
	lastLayer := serializedLayers[len(serializedLayers)-1]
	nextHdr, ok := layers.LayerToHeaderMap[lastLayer]
	if !ok {
		return 0, common.NewBasicError("unknown header", nil, "gopacket_type", lastLayer)
	}
	return nextHdr, nil
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
