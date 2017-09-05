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

// union0 represents the contents of the capnp union that starts at field @0.
type union0 struct {
	Which        proto.PathMgmt_Which
	SegReq       *SegReq
	SegReply     *SegReply
	SegReg       *SegReg
	SegSync      *SegSync
	RevInfo      *RevInfo
	IFStateReq   *IFStateReq   `capnp:"ifStateReq"`
	IFStateInfos *IFStateInfos `capnp:"ifStateInfos"`
}

func (u0 *union0) set(c proto.Cerealizable) error {
	switch u := c.(type) {
	case *SegReq:
		u0.Which = proto.PathMgmt_Which_segReq
		u0.SegReq = u
	case *SegReply:
		u0.Which = proto.PathMgmt_Which_segReply
		u0.SegReply = u
	case *SegReg:
		u0.Which = proto.PathMgmt_Which_segReg
		u0.SegReg = u
	case *SegSync:
		u0.Which = proto.PathMgmt_Which_segSync
		u0.SegSync = u
	case *RevInfo:
		u0.Which = proto.PathMgmt_Which_revInfo
		u0.RevInfo = u
	case *IFStateReq:
		u0.Which = proto.PathMgmt_Which_ifStateReq
		u0.IFStateReq = u
	case *IFStateInfos:
		u0.Which = proto.PathMgmt_Which_ifStateInfos
		u0.IFStateInfos = u
	default:
		return common.NewCError("Unsupported path mgmt union0 type (set)", "type", common.TypeOf(c))
	}
	return nil
}

func (u0 *union0) get() (proto.Cerealizable, error) {
	switch u0.Which {
	case proto.PathMgmt_Which_segReq:
		return u0.SegReq, nil
	case proto.PathMgmt_Which_segReply:
		return u0.SegReply, nil
	case proto.PathMgmt_Which_segReg:
		return u0.SegReg, nil
	case proto.PathMgmt_Which_segSync:
		return u0.SegSync, nil
	case proto.PathMgmt_Which_revInfo:
		return u0.RevInfo, nil
	case proto.PathMgmt_Which_ifStateReq:
		return u0.IFStateReq, nil
	case proto.PathMgmt_Which_ifStateInfos:
		return u0.IFStateInfos, nil
	}
	return nil, common.NewCError("Unsupported path mgmt union0 type (get)", "type", u0.Which)
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union0
}

// NewPld creates a new path mgmt payload, containing the supplied Cerealizable instance.
func NewPld(u0 proto.Cerealizable) (*Pld, error) {
	p := &Pld{}
	return p, p.union0.set(u0)
}

func (p *Pld) Union0() (proto.Cerealizable, error) {
	return p.union0.get()
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.PathMgmt_TypeID
}

func (p *Pld) String() string {
	desc := []string{"PathMgmt: Union0:"}
	u0, err := p.Union0()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", u0))
	}
	return strings.Join(desc, " ")
}
