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
// return value is 0 if the packet is SCMP General class, Unspcified type, or a
// different SCMP class, or the packet is not SCMP.
func getSCMPGeneralID(pktInfo *spkt.ScnPkt) uint64 {
	if scmpHdr, ok := pktInfo.L4.(*scmp.Hdr); ok {
		if scmpHdr.Class == scmp.C_General {
			info := pktInfo.Pld.(*scmp.Payload).Info
			if info == nil {
				return 0
			}
			switch scmpHdr.Type {
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
		}
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
	if len(extns) == 0 {
		return extns
	}
	if extns[0].Class() == common.HopByHopClass && extns[0].Type() == common.ExtnSCMPType {
		return extns[1:]
	}
	return extns
}
