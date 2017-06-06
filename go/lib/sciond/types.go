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

package sciond

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/proto"
)

type PathErrorCode uint16

const (
	ErrorOk        PathErrorCode = 0
	ErrorNoPaths   PathErrorCode = 1
	ErrorPSTimeout PathErrorCode = 2
	ErrorInternal  PathErrorCode = 3
)

func (c PathErrorCode) String() string {
	switch c {
	case ErrorOk:
		return "OK"
	case ErrorNoPaths:
		return "No paths available"
	case ErrorPSTimeout:
		return "SCIOND timed out while requesting paths"
	case ErrorInternal:
		return "SCIOND experienced an internal error"
	default:
		return fmt.Sprintf("Unknown error (%v)", uint16(c))
	}
}

type SCIONDMsg struct {
	Id                 uint64
	Which              proto.SCIONDMsg_Which
	PathReq            PathReq
	PathReply          PathReply
	AsInfoReq          ASInfoReq
	AsInfoReply        ASInfoReply
	RevNotification    RevNotification
	IfInfoRequest      IFInfoRequest
	IfInfoReply        IFInfoReply
	ServiceInfoRequest ServiceInfoRequest
	ServiceInfoReply   ServiceInfoReply
}

type PathReq struct {
	Dst      uint32
	Src      uint32
	MaxPaths uint16
	Flags    PathReqFlags
}

type PathReqFlags struct {
	Flush bool
	Sibra bool
}

type PathReply struct {
	RawErrorCode uint16 `capnp:"errorCode"`
	Entries      []PathReplyEntry
}

func (reply *PathReply) ErrorCode() PathErrorCode {
	return PathErrorCode(reply.RawErrorCode)
}

type PathReplyEntry struct {
	Path     FwdPathMeta
	HostInfo HostInfo
}

type HostInfo struct {
	Port  uint16
	Addrs struct {
		Ipv4 []byte
		Ipv6 []byte
	}
}

type FwdPathMeta struct {
	FwdPath    []byte
	Mtu        uint16
	Interfaces []PathInterface
}

type PathInterface struct {
	RawIsdas uint32 `capnp:"isdas"`
	IfID     uint64
}

func (iface *PathInterface) ISD_AS() *addr.ISD_AS {
	return addr.IAFromInt(int(iface.RawIsdas))
}

func (entry PathInterface) String() string {
	return fmt.Sprintf("%v.%v", entry.ISD_AS(), entry.IfID)
}

type ASInfoReq struct {
	Isdas uint32
}

type ASInfoReply struct {
	Entries []ASInfoReplyEntry
}

type ASInfoReplyEntry struct {
	RawIsdas uint32 `capnp:"isdas"`
	Mtu      uint16
	IsCore   bool
}

func (entry *ASInfoReplyEntry) ISD_AS() *addr.ISD_AS {
	return addr.IAFromInt(int(entry.RawIsdas))
}

func (entry ASInfoReplyEntry) String() string {
	return fmt.Sprintf("ia:%v, mtu:%v, core:%t", entry.ISD_AS(), entry.Mtu, entry.IsCore)
}

type RevNotification struct {
	RevInfo RevInfo
}

type RevInfo struct {
	IfID     uint64
	Epoch    uint16
	Nonce    []byte
	Sibling  []SiblingHash
	PrevRoot []byte
	NextRoot []byte
	Isdas    uint32
}

type SiblingHash struct {
	IsLeft bool
	Hash   []byte
}

type IFInfoRequest struct {
	IfIDs []uint64
}

type IFInfoReply struct {
	Entries []IFInfoReplyEntry
}

type IFInfoReplyEntry struct {
	IfID     uint64
	HostInfo HostInfo
}

type ServiceInfoRequest struct {
	ServiceTypes []addr.HostSVC
}

type ServiceInfoReply struct {
	Entries []ServiceInfoReplyEntry
}

type ServiceInfoReplyEntry struct {
	ServiceType addr.HostSVC
	Ttl         uint32
	HostInfos   []HostInfo
}
