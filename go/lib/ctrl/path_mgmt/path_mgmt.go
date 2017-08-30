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

	//log "github.com/inconshreveable/log15"
	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	proto.CerealBase
}

func NewPld(c proto.Cerealizable) *Pld {
	return &Pld{CerealBase: proto.NewCerealBase(c)}
}

func NewPathMgmtPldFromProto(msg proto.PathMgmt) (*Pld, *common.Error) {
	var s capnp.Struct
	p := &Pld{}
	switch msg.Which() {
	case proto.PathMgmt_Which_segReq:
		m, _ := msg.SegReq()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(&SegReq{})
	case proto.PathMgmt_Which_segReply:
		m, _ := msg.SegReply()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(NewSegReply())
	case proto.PathMgmt_Which_segReg:
		m, _ := msg.SegReg()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(NewSegReg())
	case proto.PathMgmt_Which_segSync:
		m, _ := msg.SegSync()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(NewSegSync())
	case proto.PathMgmt_Which_revInfo:
		m, _ := msg.RevInfo()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(&RevInfo{})
	case proto.PathMgmt_Which_ifStateReq:
		m, _ := msg.IfStateReq()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(&IFStateReq{})
	case proto.PathMgmt_Which_ifStateInfos:
		m, _ := msg.IfStateInfos()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(&IFStateInfos{})
	default:
		return nil, common.NewError("Unsupported PathMgmt type", "type", msg.Which())
	}
	if cerr := p.ParseProto(s); cerr != nil {
		return nil, cerr
	}
	return p, nil
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.PathMgmt_TypeID
}

func (p *Pld) ProtoType() fmt.Stringer {
	return proto.SCION_Which_pathMgmt
}

func (p *Pld) NewStruct(pa interface{}) (capnp.Struct, *common.Error) {
	type valid interface {
		NewPathMgmt() (proto.PathMgmt, error)
	}
	parent, ok := pa.(valid)
	if !ok {
		return capnp.Struct{}, common.NewError("Unsupported parent capnp type",
			"id", p.ProtoId(), "type", p.ProtoType(), "parent", fmt.Sprintf("%T", pa))
	}
	pmgmt, err := parent.NewPathMgmt()
	if err != nil {
		return capnp.Struct{}, common.NewError("Error creating struct in parent capnp",
			"id", p.ProtoId(), "type", p.ProtoType(), "parent", p, "err", err)
	}
	return p.Contents().NewStruct(pmgmt)
}

func (p *Pld) Contents() proto.Cerealizable {
	return p.CerealBase.Cerealizable
}
