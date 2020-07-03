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
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	deprecatedlayers "github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/spath"
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
		buffer.PushLayer(deprecatedlayers.LayerTypeSCIONUDP)
	case common.L4SCMP:
		buffer.PushLayer(deprecatedlayers.LayerTypeSCMP)
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
		extn, err := deprecatedlayers.ExtensionDataToExtensionLayer(nextHeaderType, extensions[i])
		if err != nil {
			return err
		}
		err = extn.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true})
		if err != nil {
			return err
		}
		switch extensions[i].Class() {
		case common.HopByHopClass:
			buffer.PushLayer(deprecatedlayers.LayerTypeHopByHopExtension)
		case common.End2EndClass:
			buffer.PushLayer(deprecatedlayers.LayerTypeEndToEndExtension)
		default:
			return serrors.New("cannot push unknown layer")
		}
	}
	return nil
}

func getNextHeaderType(buffer gopacket.SerializeBuffer) (common.L4ProtocolType, error) {
	serializedLayers := buffer.Layers()
	lastLayer := serializedLayers[len(serializedLayers)-1]
	nextHdr, ok := deprecatedlayers.LayerToHeaderMap[lastLayer]
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

// WriteScnPkt converts ScnPkt data into a raw SCION v2 header packet.
func WriteScnPkt2(s *spkt.ScnPkt, b []byte) (int, error) {
	var packetLayers []gopacket.SerializableLayer

	var scionLayer slayers.SCION
	// XXX(scrye): Set version 2 for debugging, although this is not part of the spec. This
	// should be removed once the migration to the new SCION header is finished.
	scionLayer.Version = 2
	// XXX(scrye): Do not set TrafficClass and FlowID, even though the latter is mandatory,
	// to keep things simple while we transition to HeaderV2. These should be added once
	// the transition is complete.
	scionLayer.DstIA = s.DstIA
	scionLayer.SrcIA = s.SrcIA
	netDstAddr, err := hostAddrToNetAddr(s.DstHost)
	if err != nil {
		return 0, serrors.WrapStr("converting destination addr.HostAddr to net.Addr", err,
			"address", s.DstHost)
	}
	if err := scionLayer.SetDstAddr(netDstAddr); err != nil {
		return 0, serrors.WrapStr("setting destination address", err)
	}
	netSrcAddr, err := hostAddrToNetAddr(s.SrcHost)
	if err != nil {
		return 0, serrors.WrapStr("converting source addr.HostAddr to net.Addr", err,
			"address", s.SrcHost)
	}
	if err := scionLayer.SetSrcAddr(netSrcAddr); err != nil {
		return 0, serrors.WrapStr("settting source address", err)
	}
	scionLayer.PathType = slayers.PathTypeSCION

	isOneHop := func() bool {
		if len(s.HBHExt) != 0 {
			_, ok := s.HBHExt[0].(*deprecatedlayers.ExtnOHP)
			return ok
		}
		return false
	}
	if isOneHop() {
		if !s.Path.IsHeaderV2() {
			info, err := s.Path.GetInfoField(0)
			if err != nil {
				return 0, serrors.WrapStr("extracing one hop info field", err)
			}
			hf, err := s.Path.GetHopField(spath.InfoFieldLength)
			if err != nil {
				return 0, serrors.WrapStr("extracting one hop hop field", err)
			}
			scionLayer.PathType = slayers.PathTypeOneHop
			scionLayer.Path = &onehop.Path{
				Info: path.InfoField{
					ConsDir:   true,
					Timestamp: info.TsInt,
				},
				FirstHop: path.HopField{
					ConsEgress: uint16(hf.ConsEgress),
					ExpTime:    uint8(hf.ExpTime),
				},
			}
		} else {
			var path onehop.Path
			if err := path.DecodeFromBytes(s.Path.Raw); err != nil {
				return 0, serrors.WrapStr("decoding path", err)
			}
			scionLayer.PathType = slayers.PathTypeOneHop
			scionLayer.Path = &path
		}
	} else {
		switch {
		case s.Path == nil:
			// Default nil paths to an empty SCION path
			decodedPath := scion.Decoded{
				Base: scion.Base{
					PathMeta: scion.MetaHdr{},
				},
			}
			scionLayer.Path = &decodedPath
		case s.Path.IsHeaderV2() && s.Path.IsOHP():
			var path onehop.Path
			if err := path.DecodeFromBytes(s.Path.Raw); err != nil {
				return 0, serrors.WrapStr("decoding path", err)
			}
			scionLayer.PathType = slayers.PathTypeOneHop
			scionLayer.Path = &path
		default:
			// Use decoded for simplicity, easier to work with when debugging with delve.
			var decodedPath scion.Decoded
			if err := decodedPath.DecodeFromBytes(s.Path.Raw); err != nil {
				return 0, serrors.WrapStr("decoding path", err)
			}
			scionLayer.Path = &decodedPath
		}
	}
	packetLayers = append(packetLayers, &scionLayer)

	// XXX(scrye): No extensions are defined for the V2 header format. However,
	// application code uses some V1 extensions like the One-Hop Path, and these
	// will need to be converted for V2 to the new One-Hop path type.
	if len(s.HBHExt) != 0 && !isOneHop() {
		return 0, serrors.New("HBH extensions are not supported for Header V2")
	}
	if len(s.E2EExt) != 0 {
		return 0, serrors.New("E2E extensions are not supported for Header V2")
	}

	switch layer := s.L4.(type) {
	case *l4.UDP:
		scionLayer.NextHdr = common.L4UDP
		var udpLayer slayers.UDP
		udpLayer.SrcPort = layers.UDPPort(layer.SrcPort)
		udpLayer.DstPort = layers.UDPPort(layer.DstPort)
		udpLayer.SetNetworkLayerForChecksum(&scionLayer)
		packetLayers = append(packetLayers, &udpLayer)
	case *scmp.Hdr:
		scionLayer.NextHdr = common.L4SCMP
		var scmpLayer slayers.SCMP
		scmpLayer.Class = layer.Class
		scmpLayer.Type = layer.Type
		if layer.TotalLen == 0 {
			scmpLayer.TotalLen = uint16(scmp.HdrLen + s.Pld.Len())
		} else {
			scmpLayer.TotalLen = layer.TotalLen
		}
		scmpLayer.SetNetworkLayerForChecksum(&scionLayer)
		scmpLayer.Timestamp = layer.Timestamp
		buf := make([]byte, s.Pld.Len())
		if _, err := s.Pld.WritePld(buf); err != nil {
			return 0, serrors.WrapStr("writing SCMP payload", err)
		}
		scmpLayer.Payload = buf
		packetLayers = append(packetLayers, &scmpLayer)
	}
	if _, ok := s.L4.(*scmp.Hdr); !ok {
		payloadLayer := gopacket.Payload(s.Pld.(common.RawBytes))
		packetLayers = append(packetLayers, &payloadLayer)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buffer, options, packetLayers...); err != nil {
		return 0, err
	}

	return copy(b, buffer.Bytes()), nil
}

func netAddrToHostAddr(a net.Addr) (addr.HostAddr, error) {
	switch aImpl := a.(type) {
	case *net.IPAddr:
		return addr.HostFromIP(aImpl.IP), nil
	case addr.HostSVC:
		return aImpl, nil
	default:
		return nil, serrors.New("address not supported", "a", a)
	}
}

func hostAddrToNetAddr(a addr.HostAddr) (net.Addr, error) {
	switch aImpl := a.(type) {
	case addr.HostSVC:
		return aImpl, nil
	case addr.HostIPv4, addr.HostIPv6:
		return &net.IPAddr{IP: aImpl.IP()}, nil
	default:
		return nil, serrors.New("address not supported", "a", a)
	}
}
