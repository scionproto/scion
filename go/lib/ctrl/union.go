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

package ctrl

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/extn"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/proto"
)

// union represents the contents of the unnamed capnp union.
type union struct {
	Which     proto.CtrlPld_Which
	Beacon    *seg.Beacon `capnp:"pcb"`
	IfID      *ifid.IFID  `capnp:"ifid"`
	CertMgmt  *cert_mgmt.Pld
	PathMgmt  *path_mgmt.Pld
	Sibra     []byte `capnp:"-"` // Omit for now
	DRKeyMgmt []byte `capnp:"-"` // Omit for now
	Sig       *sig_mgmt.Pld
	Extn      *extn.CtrlExtnDataList
	Ack       *ack.Ack
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *seg.Beacon:
		u.Which = proto.CtrlPld_Which_pcb
		u.Beacon = p
	case *ifid.IFID:
		u.Which = proto.CtrlPld_Which_ifid
		u.IfID = p
	case *path_mgmt.Pld:
		u.Which = proto.CtrlPld_Which_pathMgmt
		u.PathMgmt = p
	case *sig_mgmt.Pld:
		u.Which = proto.CtrlPld_Which_sig
		u.Sig = p
	case *cert_mgmt.Pld:
		u.Which = proto.CtrlPld_Which_certMgmt
		u.CertMgmt = p
	case *extn.CtrlExtnDataList:
		u.Which = proto.CtrlPld_Which_extn
		u.Extn = p
	case *ack.Ack:
		u.Which = proto.CtrlPld_Which_ack
		u.Ack = p
	default:
		return common.NewBasicError("Unsupported ctrl union type (set)", nil,
			"type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.CtrlPld_Which_pcb:
		return u.Beacon, nil
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
	case proto.CtrlPld_Which_ack:
		return u.Ack, nil
	}
	return nil, common.NewBasicError("Unsupported ctrl union type (get)", nil, "type", u.Which)
}
