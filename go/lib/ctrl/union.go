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

package ctrl

import (

	//log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/extn"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
	sigmgmt "github.com/scionproto/scion/go/sig/mgmt"
)

// union represents the contents of the unnamed capnp union.
type union struct {
	Which       proto.CtrlPld_Which
	PathSegment *seg.PathSegment `capnp:"pcb"`
	IfID        *ifid.IFID       `capnp:"ifid"`
	CertMgmt    *cert_mgmt.Pld
	PathMgmt    *path_mgmt.Pld
	Sibra       []byte `capnp:"-"` // Omit for now
	DRKeyMgmt   []byte `capnp:"-"` // Omit for now
	Sig         *sigmgmt.Pld
	Extn        *extn.CtrlExtnDataList
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *seg.PathSegment:
		u.Which = proto.CtrlPld_Which_pcb
		u.PathSegment = p
	case *ifid.IFID:
		u.Which = proto.CtrlPld_Which_ifid
		u.IfID = p
	case *path_mgmt.Pld:
		u.Which = proto.CtrlPld_Which_pathMgmt
		u.PathMgmt = p
	case *sigmgmt.Pld:
		u.Which = proto.CtrlPld_Which_sig
		u.Sig = p
	case *cert_mgmt.Pld:
		u.Which = proto.CtrlPld_Which_certMgmt
		u.CertMgmt = p
	case *extn.CtrlExtnDataList:
		u.Which = proto.CtrlPld_Which_extn
		u.Extn = p
	default:
		return common.NewCError("Unsupported ctrl union type (set)", "type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.CtrlPld_Which_pcb:
		return u.PathSegment, nil
	case proto.CtrlPld_Which_ifid:
		return u.IfID, nil
	case proto.CtrlPld_Which_pathMgmt:
		return u.PathMgmt, nil
	case proto.CtrlPld_Which_sig:
		return u.Sig, nil
	case proto.CtrlPld_Which_certMgmt:
		return u.CertMgmt, nil
	case proto.CtrlPld_Which_extn:
		return u.Extn, nil
	}
	return nil, common.NewCError("Unsupported ctrl union type (get)", "type", u.Which)
}
