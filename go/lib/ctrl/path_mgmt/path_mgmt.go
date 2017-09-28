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

package path_mgmt

import (
	"fmt"
	"strings"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

// union represents the contents of the unnamed capnp union.
type union struct {
	Which        proto.PathMgmt_Which
	SegReq       *SegReq
	SegReply     *SegReply
	SegReg       *SegReg
	SegSync      *SegSync
	RevInfo      *RevInfo
	IFStateReq   *IFStateReq   `capnp:"ifStateReq"`
	IFStateInfos *IFStateInfos `capnp:"ifStateInfos"`
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *SegReq:
		u.Which = proto.PathMgmt_Which_segReq
		u.SegReq = p
	case *SegReply:
		u.Which = proto.PathMgmt_Which_segReply
		u.SegReply = p
	case *SegReg:
		u.Which = proto.PathMgmt_Which_segReg
		u.SegReg = p
	case *SegSync:
		u.Which = proto.PathMgmt_Which_segSync
		u.SegSync = p
	case *RevInfo:
		u.Which = proto.PathMgmt_Which_revInfo
		u.RevInfo = p
	case *IFStateReq:
		u.Which = proto.PathMgmt_Which_ifStateReq
		u.IFStateReq = p
	case *IFStateInfos:
		u.Which = proto.PathMgmt_Which_ifStateInfos
		u.IFStateInfos = p
	default:
		return common.NewCError("Unsupported path mgmt union type (set)", "type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.PathMgmt_Which_segReq:
		return u.SegReq, nil
	case proto.PathMgmt_Which_segReply:
		return u.SegReply, nil
	case proto.PathMgmt_Which_segReg:
		return u.SegReg, nil
	case proto.PathMgmt_Which_segSync:
		return u.SegSync, nil
	case proto.PathMgmt_Which_revInfo:
		return u.RevInfo, nil
	case proto.PathMgmt_Which_ifStateReq:
		return u.IFStateReq, nil
	case proto.PathMgmt_Which_ifStateInfos:
		return u.IFStateInfos, nil
	}
	return nil, common.NewCError("Unsupported path mgmt union type (get)", "type", u.Which)
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union
}

// NewPld creates a new path mgmt payload, containing the supplied Cerealizable instance.
func NewPld(u proto.Cerealizable) (*Pld, error) {
	p := &Pld{}
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
