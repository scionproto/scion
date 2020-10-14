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

package path_mgmt

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

// union represents the contents of the unnamed capnp union.
type union struct {
	Which      proto.PathMgmt_Which
	SRevInfo   *SignedRevInfo
	HPSegReq   *HPSegReq   `capnp:"hpSegReq"`
	HPSegReply *HPSegReply `capnp:"hpSegReply"`
	HPSegReg   *HPSegReg   `capnp:"hpSegReg"`
	HPCfgReq   *HPCfgReq   `capnp:"hpCfgReq"`
	HPCfgReply *HPCfgReply `capnp:"hpCfgReply"`
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *SignedRevInfo:
		u.Which = proto.PathMgmt_Which_sRevInfo
		u.SRevInfo = p
	case *HPSegReq:
		u.Which = proto.PathMgmt_Which_hpSegReq
		u.HPSegReq = p
	case *HPSegReply:
		u.Which = proto.PathMgmt_Which_hpSegReply
		u.HPSegReply = p
	case *HPSegReg:
		u.Which = proto.PathMgmt_Which_hpSegReg
		u.HPSegReg = p
	case *HPCfgReq:
		u.Which = proto.PathMgmt_Which_hpCfgReq
		u.HPCfgReq = p
	case *HPCfgReply:
		u.Which = proto.PathMgmt_Which_hpCfgReply
		u.HPCfgReply = p
	default:
		return common.NewBasicError("Unsupported path mgmt union type (set)", nil,
			"type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.PathMgmt_Which_sRevInfo:
		return u.SRevInfo, nil
	case proto.PathMgmt_Which_hpSegReq:
		return u.HPSegReq, nil
	case proto.PathMgmt_Which_hpSegReply:
		return u.HPSegReply, nil
	case proto.PathMgmt_Which_hpSegReg:
		return u.HPSegReg, nil
	case proto.PathMgmt_Which_hpCfgReq:
		return u.HPCfgReq, nil
	case proto.PathMgmt_Which_hpCfgReply:
		return u.HPCfgReply, nil
	}
	return nil, common.NewBasicError("Unsupported path mgmt union type (get)", nil, "type", u.Which)
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union
	*Data
}

// NewPld creates a new path mgmt payload, containing the supplied Cerealizable instance.
func NewPld(u proto.Cerealizable, d *Data) (*Pld, error) {
	p := &Pld{Data: d}
	return p, p.union.set(u)
}

func (p *Pld) Union() (proto.Cerealizable, error) {
	return p.union.get()
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.PathMgmt_TypeID
}

func (p *Pld) String() string {
	desc := []string{"PathMgmt: Union:"}
	u, err := p.Union()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", u))
	}
	return strings.Join(desc, " ")
}

type Data struct {
	// For passing any future non-union data.
}
