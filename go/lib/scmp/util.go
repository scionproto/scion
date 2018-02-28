// Copyright 2016 ETH Zurich
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

package scmp

import (
	"github.com/scionproto/scion/go/lib/common"
)

var (
	quoteBasic = []RawBlock{RawCmnHdr, RawAddrHdr, RawL4Hdr}
	quoteAll   = append(quoteBasic, RawPathHdr, RawExtHdrs)
	quotePath  = append(quoteBasic, RawPathHdr)
	quoteExts  = append(quoteBasic, RawExtHdrs)
)

func classTypeQuotes(ct ClassType) []RawBlock {
	switch {
	case ct == ClassType{C_General, T_G_Unspecified}:
		return quoteAll
	case ct.Class == C_Routing || ct.Class == C_CmnHdr:
		return quoteBasic
	case ct == ClassType{C_Path, T_P_PathRequired}:
		return quoteBasic
	case ct.Class == C_Path:
		return quotePath
	case ct.Class == C_Ext:
		return quoteExts
	default:
		return nil
	}
}

func ParseInfo(b common.RawBytes, ct ClassType) (Info, error) {
	switch {
	case ct == ClassType{C_General, T_G_Unspecified}:
		return InfoString(b), nil
	case ct == ClassType{C_General, T_G_EchoRequest}:
		fallthrough
	case ct == ClassType{C_General, T_G_EchoReply}:
		return InfoEchoFromRaw(b)
	case ct == ClassType{C_General, T_G_TraceRouteRequest}:
		fallthrough
	case ct == ClassType{C_General, T_G_TraceRouteReply}:
		return InfoTraceRouteFromRaw(b)
	case ct == ClassType{C_General, T_G_RecordPathRequest}:
		fallthrough
	case ct == ClassType{C_General, T_G_RecordPathReply}:
		return InfoRecordPathFromRaw(b)
	case ct == ClassType{C_Routing, T_R_OversizePkt}:
		fallthrough
	case ct == ClassType{C_CmnHdr, T_C_BadPktLen}:
		return InfoPktSizeFromRaw(b)
	case ct == ClassType{C_Path, T_P_PathRequired}:
		return nil, nil
	case ct == ClassType{C_Path, T_P_RevokedIF}:
		return InfoRevocationFromRaw(b)
	case ct.Class == C_Path:
		return InfoPathOffsetsFromRaw(b)
	case ct.Class == C_Ext:
		return InfoExtIdxFromRaw(b)
	case ct.Class == C_Sibra:
		// TODO(kormat): not defined/handled yet.
	}
	return nil, nil
}
