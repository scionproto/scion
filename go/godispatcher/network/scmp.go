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

package network

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
)

func isSCMPGeneralRequest(header *scmp.Hdr) bool {
	if header.Class == scmp.C_General {
		return header.Type == scmp.T_G_EchoRequest ||
			header.Type == scmp.T_G_TraceRouteRequest ||
			header.Type == scmp.T_G_RecordPathRequest
	}
	return false
}

func isSCMPGeneralReply(header *scmp.Hdr) bool {
	if header.Class == scmp.C_General {
		return header.Type == scmp.T_G_EchoReply ||
			header.Type == scmp.T_G_TraceRouteReply ||
			header.Type == scmp.T_G_RecordPathReply
	}
	return false
}

// getSCMPGeneralID returns the 8-byte ID of a SCMP General class packet. The
// return value is 0 if the packet is (1) SCMP General class with unspecified
// type, or (2) a non-General SCMP class, or (3) the packet is not SCMP.
func getSCMPGeneralID(pktInfo *spkt.ScnPkt) uint64 {
	if scmpHdr, ok := pktInfo.L4.(*scmp.Hdr); ok {
		if scmpHdr.Class == scmp.C_General {
			info := pktInfo.Pld.(*scmp.Payload).Info
			return extractID(scmpHdr.Type, info)
		}
	}
	return 0
}

// getSCMPQuoteID returns the 8-byte ID of a quoted SCMP General class packet.
func getQuotedSCMPGeneralID(scmpPayload *scmp.Payload) (uint64, error) {
	// FIXME(scrye): In the case of an SCMP quote, the L4 header quote
	// contains both the SCMP Meta and SCMP Info Payload fields of the
	// offending packet. This, however, is not defined (or parsed) as an
	// SCMP header. We skip past the canonical 16 bytes of the header here,
	// to extract the Info field of the offending packet.
	quotedSCMPHeader, err := scmp.HdrFromRaw(scmpPayload.L4Hdr)
	if err != nil {
		return 0, err
	}
	meta, err := scmp.MetaFromRaw(scmpPayload.L4Hdr[quotedSCMPHeader.L4Len():])
	if err != nil {
		return 0, err
	}
	quotedInfoStart := quotedSCMPHeader.L4Len() + common.LineLen
	quotedInfoEnd := quotedInfoStart + int(meta.InfoLen)*common.LineLen
	if len(scmpPayload.L4Hdr) < quotedInfoEnd {
		return 0, common.NewBasicError("incomplete post-quoted SCMP header meta+info quote", nil)
	}
	info, err := scmp.ParseInfo(scmpPayload.L4Hdr[quotedInfoStart:quotedInfoEnd],
		scmp.ClassType{Class: quotedSCMPHeader.Class, Type: quotedSCMPHeader.Type})
	if err != nil {
		return 0, err
	}
	id := extractID(quotedSCMPHeader.Type, info)
	if id == 0 {
		return 0, common.NewBasicError("SCMP General ID is 0, cannot route error packet", nil)
	}
	return id, nil
}

// extractID returns the ID contained in the info field. If info is nil, or a
// type that doesn't contain an ID, it returns 0.
func extractID(t scmp.Type, info scmp.Info) uint64 {
	if info == nil {
		return 0
	}
	switch t {
	case scmp.T_G_EchoRequest, scmp.T_G_EchoReply:
		infoEcho := info.(*scmp.InfoEcho)
		return infoEcho.Id
	case scmp.T_G_RecordPathRequest, scmp.T_G_RecordPathReply:
		infoRecordPath := info.(*scmp.InfoRecordPath)
		return infoRecordPath.Id
	case scmp.T_G_TraceRouteRequest, scmp.T_G_TraceRouteReply:
		infoTraceRoute := info.(*scmp.InfoTraceRoute)
		return infoTraceRoute.Id
	}
	return 0
}

// invertSCMPGeneralType converts SCMP General class requests to replies, and
// viceversa. All other SCMP packets are unchanged.
func invertSCMPGeneralType(header *scmp.Hdr) {
	switch header.Type {
	case scmp.T_G_EchoReply:
		header.Type = scmp.T_G_EchoRequest
	case scmp.T_G_RecordPathReply:
		header.Type = scmp.T_G_RecordPathRequest
	case scmp.T_G_TraceRouteReply:
		header.Type = scmp.T_G_TraceRouteRequest
	case scmp.T_G_EchoRequest:
		header.Type = scmp.T_G_EchoReply
	case scmp.T_G_RecordPathRequest:
		header.Type = scmp.T_G_RecordPathReply
	case scmp.T_G_TraceRouteRequest:
		header.Type = scmp.T_G_TraceRouteReply
	}
}

// removeSCMPHBH removes the first HBH extension if is an SCMP extension, and
// returns the updated slice.
//
// If the first extension is not SCMP, or if the SCMP HBH is in another place
// (incorrect as defined by SCION, as SCMP HBH needs to be first), the list of
// extensions is unchanged.
func removeSCMPHBH(extns []common.Extension) []common.Extension {
	if len(extns) > 0 &&
		extns[0].Class() == common.HopByHopClass &&
		extns[0].Type() == common.ExtnSCMPType {
		return extns[1:]
	}
	return extns
}
