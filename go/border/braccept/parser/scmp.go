// Copyright 2019 ETH Zurich
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

package parser

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	golayers "github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/border/braccept/layers"
	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/proto"
)

var _ TaggedLayer = (*SCMPTaggedLayer)(nil)

type SCMPTaggedLayer struct {
	layers.SCMP
	metaKVS propMap
	tagged
	options
}

func SCMPParser(lines []string) TaggedLayer {
	// default SCMP layer values
	s := &SCMPTaggedLayer{}
	// XXX Not having this empty slice makes restruct.Pack generate bad binary representation.
	s.Checksum = make([]byte, 2)
	s.Pld = &scmp.Payload{}
	s.Pld.Meta = &scmp.Meta{}

	//SerializeOptions
	s.opts.ComputeChecksums = true
	s.opts.FixLengths = true

	s.Update(lines)
	return s
}

func (s *SCMPTaggedLayer) Layer() gopacket.Layer {
	return &s.SCMP
}

func (s *SCMPTaggedLayer) Clone() TaggedLayer {
	clone := *s
	return &clone
}

func (s *SCMPTaggedLayer) String() string {
	return gopacket.LayerString(&s.SCMP)
}

func (s *SCMPTaggedLayer) Update(lines []string) {
	if s == nil {
		panic(fmt.Errorf("SCMP Tagged Layer is nil!\n"))
	}
	skip := 0
	for i := range lines {
		if skip > 0 {
			skip -= 1
			continue
		}
		line := lines[i]

		layerType, tag, kvStr := decodeLayerLine(line)
		kvs := getKeyValueMap(kvStr)
		switch layerType {
		case "SCMP":
			s.tag = tag
			s.updateHeaderFields(kvs)
		case "META":
			// XXX We wait until the end to update fields, using defaults from QUOTED packet
			s.metaKVS = kvs
		case "InfoRevocation":
			info := &InfoRevocation{}
			skip = info.parse(lines[i:])
			s.Info = info
		case "QUOTED":
			s.updateQuotes(kvs)
		default:
			panic(fmt.Errorf("Unknown SCMP sub layer type '%s'\n", layerType))
		}
	}
	s.updateMetaFields(s.metaKVS)
}

type InfoRevocation struct {
	scmp.InfoRevocation
}

func (info *InfoRevocation) parse(lines []string) int {
	var err error
	if len(lines) < 2 {
		panic(fmt.Errorf("Bad InfoRevocation layer!\n%s\n", strings.Join(lines, "\n")))
	}
	_, _, kvStr := decodeLayerLine(lines[0])
	kvs := getKeyValueMap(kvStr)

	ipo := &InfoPathOffsets{}
	ipo.updateFields(kvs)
	info.InfoPathOffsets = &ipo.InfoPathOffsets
	// Parse RevInfo
	rev := &RevInfo{}
	layerType, _, kvStr := decodeLayerLine(lines[1])
	if layerType != "SignedRevInfo" {
		panic(fmt.Errorf("Bad SignedRevInfo layer!\n%s\n", lines[1]))
	}
	kvs = getKeyValueMap(kvStr)
	rev.updateFields(kvs)

	srev := rev.sign()
	info.RawSRev, err = proto.PackRoot(srev)
	if err != nil {
		panic(err)
	}
	return 1
}

type InfoPathOffsets struct {
	scmp.InfoPathOffsets
}

func (i *InfoPathOffsets) updateFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "InfoF":
			i.InfoF = uint8(StrToInt(v))
		case "HopF":
			i.HopF = uint8(StrToInt(v))
		case "IfID":
			i.IfID = common.IFIDType(StrToInt(v))
		case "Ingress":
			i.Ingress = StrToBool(v)
		default:
			panic(fmt.Errorf("Unknown InfoPathOffsets field: %s", k))
		}
	}
}

func (s *SCMPTaggedLayer) updateHeaderFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "Class":
			s.parseSCMPClass(v)
		case "Type":
			s.parseSCMPType(v)
		case "Length":
			s.TotalLen = uint16(StrToInt(v))
			s.opts.FixLengths = false
		case "Checksum":
			s.Checksum = make(common.RawBytes, 2)
			common.Order.PutUint16(s.Checksum, uint16(HexToInt(v)))
			s.opts.ComputeChecksums = false
		case "Timestamp":
			var err error
			t := shared.Now
			if v != "now" {
				t, err = time.Parse(common.TimeFmt, v)
				if err != nil {
					panic(err)
				}
			}
			s.SetTime(t)
		default:
			panic(fmt.Errorf("Unknown SCMP field: %s", k))
		}
	}
}

func (s *SCMPTaggedLayer) parseSCMPClass(c string) {
	switch c {
	case "GENERAL":
		s.Class = scmp.C_General
	case "ROUTING":
		s.Class = scmp.C_Routing
	case "CMNHDR":
		s.Class = scmp.C_CmnHdr
	case "PATH":
		s.Class = scmp.C_Path
	case "EXT":
		s.Class = scmp.C_Ext
	case "SIBRA":
		s.Class = scmp.C_Sibra
	default:
		if c[:2] == "0x" {
			s.Class = scmp.Class(HexToInt(c[2:]))
		}
		panic(fmt.Errorf("Unknown SCMP Class '%s'", c))
	}
}

func (s *SCMPTaggedLayer) parseSCMPType(c string) {
	switch c {
	case "UNSPECIFIED":
		s.Type = scmp.T_G_Unspecified
	case "ECHO_REQUEST":
		s.Type = scmp.T_G_EchoRequest
	case "ECHO_REPLY":
		s.Type = scmp.T_G_EchoReply
	case "TRACE_ROUTE_REQUEST":
		s.Type = scmp.T_G_TraceRouteRequest
	case "TRACE_ROUTE_REPLY":
		s.Type = scmp.T_G_TraceRouteReply
	case "RECORD_PATH_REQUEST":
		s.Type = scmp.T_G_RecordPathRequest
	case "RECORD_PATH_REPLY":
		s.Type = scmp.T_G_RecordPathReply
	case "UNREACH_NET":
		s.Type = scmp.T_R_UnreachNet
	case "UNREACH_HOST":
		s.Type = scmp.T_R_UnreachHost
	case "L2_ERROR":
		s.Type = scmp.T_R_L2Error
	case "UNREACH_PROTO":
		s.Type = scmp.T_R_UnreachProto
	case "UNREACH_PORT":
		s.Type = scmp.T_R_UnreachPort
	case "UNKNOWN_HOST":
		s.Type = scmp.T_R_UnknownHost
	case "BAD_HOST":
		s.Type = scmp.T_R_BadHost
	case "OVERSIZE_PKT":
		s.Type = scmp.T_R_OversizePkt
	case "ADMIN_DENIED":
		s.Type = scmp.T_R_AdminDenied
	case "BAD_VERSION":
		s.Type = scmp.T_C_BadVersion
	case "BAD_DST_TYPE":
		s.Type = scmp.T_C_BadDstType
	case "BAD_SRC_TYPE":
		s.Type = scmp.T_C_BadSrcType
	case "BAD_PKT_LEN":
		s.Type = scmp.T_C_BadPktLen
	case "BAD_IOF_OFFSET":
		s.Type = scmp.T_C_BadInfoFOffset
	case "BAD_HOF_OFFSET":
		s.Type = scmp.T_C_BadHopFOffset
	case "PATH_REQUIRED":
		s.Type = scmp.T_P_PathRequired
	case "BAD_MAC":
		s.Type = scmp.T_P_BadMac
	case "EXPIRED_HOPF":
		s.Type = scmp.T_P_ExpiredHopF
	case "BAD_IF":
		s.Type = scmp.T_P_BadIF
	case "REVOKED_IF":
		s.Type = scmp.T_P_RevokedIF
	case "NON_ROUTING_HOPF":
		s.Type = scmp.T_P_NonRoutingHopF
	case "DELIVERY_NON_LOCAL":
		s.Type = scmp.T_P_DeliveryNonLocal
	case "BAD_SEGMENT":
		s.Type = scmp.T_P_BadSegment
	case "BAD_INFO_FIELD":
		s.Type = scmp.T_P_BadInfoField
	case "BAD_HOP_FIELD":
		s.Type = scmp.T_P_BadHopField
	case "TOO_MANY_HOPBYHOP":
		s.Type = scmp.T_E_TooManyHopbyHop
	case "BAD_EXT_ORDER":
		s.Type = scmp.T_E_BadExtOrder
	case "BAD_HOPBYHOP":
		s.Type = scmp.T_E_BadHopByHop
	case "BAD_END2END":
		s.Type = scmp.T_E_BadEnd2End
	case "SIBRA_BAD_VERSION":
		s.Type = scmp.T_S_BadVersion
	case "SETUP_NO_REQ":
		s.Type = scmp.T_S_SetupNoReq
	default:
		if c[:2] == "0x" {
			s.Type = scmp.Type(HexToInt(c[2:]))
		}
		panic(fmt.Errorf("Unknown SCMP Type '%s'", c))
	}
}

func (s *SCMPTaggedLayer) updateMetaFields(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "InfoLen":
			s.Meta.InfoLen = uint8(StrToInt(v))
		case "CmnHdrLen":
			s.Meta.CmnHdrLen = uint8(StrToInt(v))
		case "AddrHdrLen":
			s.Meta.AddrHdrLen = uint8(StrToInt(v))
		case "PathHdrLEn":
			s.Meta.PathHdrLen = uint8(StrToInt(v))
		case "ExtHdrsLen":
			s.Meta.ExtHdrsLen = uint8(StrToInt(v))
		case "L4HdrLen":
			s.Meta.L4HdrLen = uint8(StrToInt(v))
		case "L4Proto":
			s.Meta.L4Proto = parseScionProto(v)
		default:
			panic(fmt.Errorf("Unknown SCMP META field: %s", k))
		}
	}
}

func (s *SCMPTaggedLayer) updateQuotes(kvs propMap) {
	for k, v := range kvs {
		switch k {
		case "RawPkt":
			s.generatePayload(v)
		default:
			panic(fmt.Errorf("Unknown SCMP QUOTE field: %s", k))
		}
	}
}

func (s *SCMPTaggedLayer) generatePayload(rawPkt string) {
	raw := HexToBytes(rawPkt)
	// Build and parse the packet sent, which will be used to generate the expected quotes
	pkt := gopacket.NewPacket(raw, golayers.LayerTypeEthernet, gopacket.NoCopy)
	// Find SCION layer
	pktLayers := pkt.Layers()
	for i := range pktLayers {
		if pktLayers[i].LayerType() == layers.LayerTypeScion {
			pktLayers = pktLayers[i:]
			break
		}
	}
	if len(pktLayers) == len(pkt.Layers()) {
		panic(fmt.Errorf("Failed to generate expected SCMP quotes (SCION layer parsing)"))
	}
	scn := pktLayers[0].(*layers.Scion)
	qr := &quoteRaw{scion: scn}
	// Find L4 layer
	var l4Proto common.L4ProtocolType
	for idx := range pktLayers {
		l := pktLayers[idx]
		switch l.LayerType() {
		case layers.LayerTypeSCMP:
			qr.l4 = l
			l4Proto = common.L4SCMP
			break
		case golayers.LayerTypeUDP:
			qr.l4 = l
			l4Proto = common.L4UDP
			break
		}
	}
	if qr.l4 == nil {
		// XXX Likely a SCION extension parse error
		qr.l4 = pktLayers[len(pktLayers)]
	}
	ct := scmp.ClassType{Class: s.Class, Type: s.Type}
	pld := scmp.PldFromQuotes(ct, s.Info, l4Proto, qr.getRaw)
	s.Pld = pld
}

type quoteRaw struct {
	scion *layers.Scion
	l4    gopacket.Layer
}

// getRaw returns slices of the underlying buffer corresponding to part of the
// packet identified by the blk argument. This is used, for example, by SCMP to
// quote parts of the packet in an error response.
func (qr *quoteRaw) getRaw(blk scmp.RawBlock) common.RawBytes {
	scnRaw := qr.scion.Contents
	addrLen := qr.scion.AddrHdr.Len()
	scnPld := qr.scion.Payload
	extLen := len(scnPld) - len(qr.l4.LayerContents()) - len(qr.l4.LayerPayload())
	switch blk {
	case scmp.RawCmnHdr:
		return scnRaw[:spkt.CmnHdrLen]
	case scmp.RawAddrHdr:
		return scnRaw[spkt.CmnHdrLen : spkt.CmnHdrLen+addrLen]
	case scmp.RawPathHdr:
		return scnRaw[spkt.CmnHdrLen+addrLen:]
	case scmp.RawExtHdrs:
		return scnPld[:extLen]
	case scmp.RawL4Hdr:
		if s, ok := qr.l4.(*layers.SCMP); ok {
			return qr.l4.LayerContents()[:scmp.HdrLen+s.Meta.InfoLen*common.LineLen]
		}
		return qr.l4.LayerContents()
	}
	return nil
}
