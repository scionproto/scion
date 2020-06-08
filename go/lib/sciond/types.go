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

package sciond

import (
	"fmt"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/hostinfo"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

type PathErrorCode uint16

const (
	ErrorOk PathErrorCode = iota
	ErrorNoPaths
	ErrorPSTimeout
	ErrorInternal
	ErrorBadSrcIA
	ErrorBadDstIA
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
	case ErrorBadSrcIA:
		return "Bad source ISD/AS"
	case ErrorBadDstIA:
		return "Bad destination ISD/AS"
	default:
		return fmt.Sprintf("Unknown error (%v)", uint16(c))
	}
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	Id                 uint64
	TraceId            []byte
	Which              proto.SCIONDMsg_Which
	PathReq            *PathReq
	PathReply          *PathReply
	AsInfoReq          *ASInfoReq
	AsInfoReply        *ASInfoReply
	RevNotification    *RevNotification
	RevReply           *RevReply
	IfInfoRequest      *IFInfoRequest
	IfInfoReply        *IFInfoReply
	ServiceInfoRequest *ServiceInfoRequest
	ServiceInfoReply   *ServiceInfoReply
}

func NewPldFromRaw(b common.RawBytes) (*Pld, error) {
	p := &Pld{}
	return p, proto.ParseFromRaw(p, b)
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.SCIONDMsg_TypeID
}

func (p *Pld) String() string {
	desc := []string{fmt.Sprintf("Sciond: Id: %d Union: ", p.Id)}
	u1, err := p.union()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", u1))
	}
	return strings.Join(desc, "")
}

func (p *Pld) union() (interface{}, error) {
	switch p.Which {
	case proto.SCIONDMsg_Which_pathReq:
		return p.PathReq, nil
	case proto.SCIONDMsg_Which_pathReply:
		return p.PathReply, nil
	case proto.SCIONDMsg_Which_asInfoReq:
		return p.AsInfoReq, nil
	case proto.SCIONDMsg_Which_asInfoReply:
		return p.AsInfoReply, nil
	case proto.SCIONDMsg_Which_revNotification:
		return p.RevNotification, nil
	case proto.SCIONDMsg_Which_revReply:
		return p.RevReply, nil
	case proto.SCIONDMsg_Which_ifInfoRequest:
		return p.IfInfoRequest, nil
	case proto.SCIONDMsg_Which_ifInfoReply:
		return p.IfInfoReply, nil
	case proto.SCIONDMsg_Which_serviceInfoRequest:
		return p.ServiceInfoRequest, nil
	case proto.SCIONDMsg_Which_serviceInfoReply:
		return p.ServiceInfoReply, nil
	}
	return nil, common.NewBasicError("Unsupported SCIOND union type", nil, "type", p.Which)
}

type PathReq struct {
	Dst    addr.IAInt
	Src    addr.IAInt
	HPCfgs []*path_mgmt.HPGroupId `capnp:"hpCfgs"`
	Flags  PathReqFlags
}

func (pathReq *PathReq) Copy() *PathReq {
	if pathReq == nil {
		return nil
	}
	return &PathReq{
		Dst:   pathReq.Dst,
		Src:   pathReq.Src,
		Flags: pathReq.Flags,
	}
}

func (pathReq *PathReq) String() string {
	return fmt.Sprintf("%v -> %v, flags=%v",
		pathReq.Src, pathReq.Dst, pathReq.Flags)
}

type PathReqFlags struct {
	PathCount uint16 `capnp:"-"`
	Refresh   bool
	Hidden    bool
}

type PathReply struct {
	ErrorCode PathErrorCode
	Entries   []PathReplyEntry
}

func (r *PathReply) String() string {
	strEntries := make([]string, len(r.Entries))
	for i := range r.Entries {
		strEntries[i] = r.Entries[i].String()
	}
	return fmt.Sprintf("ErrorCode=%v\n  %v", r.ErrorCode, strings.Join(strEntries, "\n  "))
}

type PathReplyEntry struct {
	Path     *FwdPathMeta
	HostInfo hostinfo.Host
	StaticInfo *PathMetadata `capnp:"pathStaticInfo"`
}

func (e *PathReplyEntry) Copy() *PathReplyEntry {
	if e == nil {
		return nil
	}
	return &PathReplyEntry{
		Path:     e.Path.Copy(),
		HostInfo: *e.HostInfo.Copy(),
	}
}

func (e *PathReplyEntry) String() string {
	return fmt.Sprintf("%v NextHop=%v", e.Path, &e.HostInfo)
}

type FwdPathMeta struct {
	FwdPath    []byte
	Mtu        uint16
	Interfaces []PathInterface
	ExpTime    uint32
}

func (fpm *FwdPathMeta) SrcIA() addr.IA {
	ifaces := fpm.Interfaces
	if len(ifaces) == 0 {
		return addr.IA{}
	}
	return ifaces[0].IA()
}

func (fpm *FwdPathMeta) DstIA() addr.IA {
	ifaces := fpm.Interfaces
	if len(ifaces) == 0 {
		return addr.IA{}
	}
	return ifaces[len(ifaces)-1].IA()
}

func (fpm *FwdPathMeta) Expiry() time.Time {
	return util.SecsToTime(fpm.ExpTime)
}

func (fpm *FwdPathMeta) Copy() *FwdPathMeta {
	if fpm == nil {
		return nil
	}
	res := &FwdPathMeta{Mtu: fpm.Mtu, ExpTime: fpm.ExpTime}
	res.FwdPath = common.CloneByteSlice(fpm.FwdPath)
	if fpm.Interfaces != nil {
		res.Interfaces = make([]PathInterface, len(fpm.Interfaces))
		copy(res.Interfaces, fpm.Interfaces)
	}
	return res
}

func (fpm *FwdPathMeta) String() string {
	hops := fpm.fmtIfaces()
	return fmt.Sprintf("Hops: [%s] Mtu: %d", strings.Join(hops, ">"), fpm.Mtu)
}

func (fpm *FwdPathMeta) fmtIfaces() []string {
	var hops []string
	if len(fpm.Interfaces) == 0 {
		return hops
	}
	intf := fpm.Interfaces[0]
	hops = append(hops, fmt.Sprintf("%s %d", intf.IA(), intf.IfID))
	for i := 1; i < len(fpm.Interfaces)-1; i += 2 {
		inIntf := fpm.Interfaces[i]
		outIntf := fpm.Interfaces[i+1]
		hops = append(hops, fmt.Sprintf("%d %s %d", inIntf.IfID, inIntf.IA(), outIntf.IfID))
	}
	intf = fpm.Interfaces[len(fpm.Interfaces)-1]
	hops = append(hops, fmt.Sprintf("%d %s", intf.IfID, intf.IA()))
	return hops
}

type PathInterface struct {
	RawIsdas addr.IAInt `capnp:"isdas"`
	IfID     common.IFIDType
}

func (iface PathInterface) IA() addr.IA {
	return iface.RawIsdas.IA()
}

func (iface PathInterface) ID() common.IFIDType {
	return iface.IfID
}

func (iface *PathInterface) Equal(other *PathInterface) bool {
	if iface == nil || other == nil {
		return iface == other
	}
	return iface.RawIsdas == other.RawIsdas && iface.IfID == other.IfID
}

func (iface PathInterface) String() string {
	return fmt.Sprintf("%s#%d", iface.IA(), iface.IfID)
}

type ASInfoReq struct {
	Isdas addr.IAInt
}

func (r ASInfoReq) String() string {
	return r.Isdas.String()
}

type ASInfoReply struct {
	Entries []ASInfoReplyEntry
}

type ASInfoReplyEntry struct {
	RawIsdas addr.IAInt `capnp:"isdas"`
	Mtu      uint16
	IsCore   bool
}

func (entry *ASInfoReplyEntry) ISD_AS() addr.IA {
	return entry.RawIsdas.IA()
}

func (entry ASInfoReplyEntry) String() string {
	return fmt.Sprintf("ia:%v, mtu:%v, core:%t", entry.ISD_AS(), entry.Mtu, entry.IsCore)
}

type RevNotification struct {
	SRevInfo *path_mgmt.SignedRevInfo
}

func (rN *RevNotification) String() string {
	return fmt.Sprintf("SRevInfo: %s", rN.SRevInfo)
}

type RevReply struct {
	Result RevResult
}

type RevResult uint16

const (
	RevValid RevResult = iota
	RevStale
	RevInvalid
	RevUnknown
)

func (c RevResult) String() string {
	switch c {
	case RevValid:
		return "RevValid"
	case RevStale:
		return "RevStale"
	case RevInvalid:
		return "RevInvalid"
	case RevUnknown:
		return "RevUnknown"
	default:
		return fmt.Sprintf("Unknown revocation result (%d)", c)
	}
}

type IFInfoRequest struct {
	IfIDs []common.IFIDType
}

func (r IFInfoRequest) String() string {
	return fmt.Sprintf("%v", r.IfIDs)
}

type IFInfoReply struct {
	RawEntries []IFInfoReplyEntry `capnp:"entries"`
}

type IFInfoReplyEntry struct {
	IfID     common.IFIDType
	HostInfo hostinfo.Host
}

type ServiceInfoRequest struct {
	ServiceTypes []proto.ServiceType
}

func (r ServiceInfoRequest) String() string {
	return fmt.Sprintf("%v", r.ServiceTypes)
}

type ServiceInfoReply struct {
	Entries []ServiceInfoReplyEntry
}

type ServiceInfoReplyEntry struct {
	ServiceType proto.ServiceType
	Ttl         uint32
	HostInfos   []hostinfo.Host
}
