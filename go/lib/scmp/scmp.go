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
	"fmt"
	//log "github.com/inconshreveable/log15"
)

// https://github.com/scionproto/scion/blob/master/lib/packet/scmp/types.py

type Class uint16

const (
	C_General Class = iota
	C_Routing
	C_CmnHdr
	C_Path
	C_Ext
	C_Sibra
)

var classNames = []string{"GENERAL", "ROUTING", "CMNHDR", "PATH", "EXT", "SIBRA"}

func (c Class) String() string {
	if int(c) > len(classNames) {
		return fmt.Sprintf("Class(%d)", c)
	}
	return fmt.Sprintf("%s(%d)", classNames[c], c)
}

type Type uint16

// C_General types
const (
	T_G_Unspecified Type = iota
	T_G_EchoRequest
	T_G_EchoReply
)

// C_Routing types
const (
	T_R_UnreachNet Type = iota
	T_R_UnreachHost
	T_R_L2Error
	T_R_UnreachProto
	T_R_UnreachPort
	T_R_UnknownHost
	T_R_BadHost
	T_R_OversizePkt
	T_R_AdminDenied
)

// C_CmnHdr types
const (
	T_C_BadVersion Type = iota
	T_C_BadDstType
	T_C_BadSrcType
	T_C_BadPktLen
	T_C_BadInfoFOffset
	T_C_BadHopFOffset
)

// C_Path types
const (
	T_P_PathRequired Type = iota
	T_P_BadMac
	T_P_ExpiredHopF
	T_P_BadIF
	T_P_RevokedIF
	T_P_NonRoutingHopF
	T_P_DeliveryFwdOnly
	T_P_DeliveryNonLocal
	T_P_BadSegment
	T_P_BadInfoField
	T_P_BadHopField
)

// C_Ext types
const (
	T_E_TooManyHopbyHop Type = iota
	T_E_BadExtOrder
	T_E_BadHopByHop
	T_E_BadEnd2End
)

// C_Sibra types
const (
	T_S_BadVersion Type = iota
	T_S_SetupNoReq
)

var typeNameMap = map[Class][]string{
	C_General: {"UNSPECIFIED", "ECHO_REQEST", "ECHO_REPLY"},
	C_Routing: {"UNREACH_NET", "UNREACH_HOST", "L2_ERROR", "UNREACH_PROTO",
		"UNREACH_PORT", "UNKNOWN_HOST", "BAD_HOST", "OVERSIZE_PKT", "ADMIN_DENIED"},
	C_CmnHdr: {"BAD_VERSION", "BAD_DST_TYPE", "BAD_SRC_TYPE",
		"BAD_PKT_LEN", "BAD_IOF_OFFSET", "BAD_HOF_OFFSET"},
	C_Path: {"PATH_REQUIRED", "BAD_MAC", "EXPIRED_HOPF", "BAD_IF", "REVOKED_IF",
		"NON_ROUTING_HOPF", "DELIVERY_FWD_ONLY", "DELIVERY_NON_LOCAL", "BAD_SEGMENT",
		"BAD_INFO_FIELD", "BAD_HOP_FIELD",
	},
	C_Ext:   {"TOO_MANY_HOPBYHOP", "BAD_EXT_ORDER", "BAD_HOPBYHOP", "BAD_END2END"},
	C_Sibra: {"BAD_VERSION", "SETUP_NO_REQ"},
}

func (t Type) Name(c Class) string {
	names, ok := typeNameMap[c]
	if !ok || int(t) > len(names) {
		return fmt.Sprintf("Type(%d)", t)
	}
	return fmt.Sprintf("%s(%d)", names[t], t)
}

type ClassType struct {
	Class Class
	Type  Type
}

func (ct ClassType) String() string {
	return fmt.Sprintf("%v:%v", ct.Class, ct.Type.Name(ct.Class))
}

// Used to specify parts of packets to quote
type RawBlock int

const (
	RawCmnHdr RawBlock = iota
	RawAddrHdr
	RawPathHdr
	RawExtHdrs
	RawL4Hdr
)

// Used as part of common.NewErrorData to indicate which SCMP error should be generated.
type ErrData struct {
	CT   ClassType
	Info Info
}

func NewErrData(class Class, type_ Type, info Info) *ErrData {
	return &ErrData{CT: ClassType{class, type_}, Info: info}
}

func (e *ErrData) String() string {
	return fmt.Sprintf("CT: %v Info: %v", e.CT, e.Info)
}
