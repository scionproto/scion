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

func (cts *union) set(c proto.Cerealizable) error {
	switch u := c.(type) {
	case *SegReq:
		cts.Which = proto.PathMgmt_Which_segReq
		cts.SegReq = u
	case *SegReply:
		cts.Which = proto.PathMgmt_Which_segReply
		cts.SegReply = u
	case *SegReg:
		cts.Which = proto.PathMgmt_Which_segReg
		cts.SegReg = u
	case *SegSync:
		cts.Which = proto.PathMgmt_Which_segSync
		cts.SegSync = u
	case *RevInfo:
		cts.Which = proto.PathMgmt_Which_revInfo
		cts.RevInfo = u
	case *IFStateReq:
		cts.Which = proto.PathMgmt_Which_ifStateReq
		cts.IFStateReq = u
	case *IFStateInfos:
		cts.Which = proto.PathMgmt_Which_ifStateInfos
		cts.IFStateInfos = u
	default:
		return common.NewCError("Unsupported path mgmt union type (set)", "type", common.TypeOf(c))
	}
	return nil
}

func (cts *union) get() (proto.Cerealizable, error) {
	switch cts.Which {
	case proto.PathMgmt_Which_segReq:
		return cts.SegReq, nil
	case proto.PathMgmt_Which_segReply:
		return cts.SegReply, nil
	case proto.PathMgmt_Which_segReg:
		return cts.SegReg, nil
	case proto.PathMgmt_Which_segSync:
		return cts.SegSync, nil
	case proto.PathMgmt_Which_revInfo:
		return cts.RevInfo, nil
	case proto.PathMgmt_Which_ifStateReq:
		return cts.IFStateReq, nil
	case proto.PathMgmt_Which_ifStateInfos:
		return cts.IFStateInfos, nil
	}
	return nil, common.NewCError("Unsupported path mgmt union type (get)", "type", cts.Which)
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union
}

// NewPld creates a new path mgmt payload, containing the supplied Cerealizable instance.
func NewPld(cts proto.Cerealizable) (*Pld, error) {
	p := &Pld{}
	return p, p.union.set(cts)
}

func (p *Pld) Union() (proto.Cerealizable, error) {
	return p.union.get()
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.PathMgmt_TypeID
}

func (p *Pld) String() string {
	desc := []string{"PathMgmt: Union:"}
	cts, err := p.Union()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", cts))
	}
	return strings.Join(desc, " ")
}
