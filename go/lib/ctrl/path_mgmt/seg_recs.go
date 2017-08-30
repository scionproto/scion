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

// This file contains the Go representation of segment records.

package path_mgmt

import (
	"fmt"
	"strings"

	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*segRecsBase)(nil)

type segRecsBase struct {
	Recs       []*seg.Meta
	RevInfos   []*RevInfo
	protoWhich proto.PathMgmt_Which
}

func newSegRecBase(which proto.PathMgmt_Which) *segRecsBase {
	return &segRecsBase{protoWhich: which}
}

func (s *segRecsBase) ProtoId() proto.ProtoIdType {
	return proto.SegReq_TypeID
}

func (s *segRecsBase) ProtoType() fmt.Stringer {
	return s.protoWhich
}

func (s *segRecsBase) NewStruct(p interface{}) (capnp.Struct, *common.Error) {
	type valid interface {
		NewSegRecs() (proto.SegRecs, error)
	}
	parent, ok := p.(valid)
	if !ok {
		return capnp.Struct{}, common.NewError("Unsupported parent capnp type",
			"id", s.ProtoId(), "type", s.ProtoType(), "parent", fmt.Sprintf("%T", p))
	}
	n, err := parent.NewSegRecs()
	if err != nil {
		return capnp.Struct{}, common.NewError("Error creating struct in parent capnp",
			"id", s.ProtoId(), "type", s.ProtoType(), "parent", p, "err", err)
	}
	return n.Struct, nil
}

func (s *segRecsBase) String() string {
	desc := []string{"Recs:"}
	for _, m := range s.Recs {
		desc = append(desc, m.String())
	}
	if len(s.RevInfos) > 0 {
		desc = append(desc, "RevInfos")
		for _, info := range s.RevInfos {
			desc = append(desc, info.String())
		}
	}
	return strings.Join(desc, "\n")
}

type SegReply struct {
	*segRecsBase
}

func NewSegReply() *SegReply {
	return &SegReply{newSegRecBase(proto.PathMgmt_Which_segReply)}
}

type SegReg struct {
	*segRecsBase
}

func NewSegReg() *SegReg {
	return &SegReg{newSegRecBase(proto.PathMgmt_Which_segReg)}
}

type SegSync struct {
	*segRecsBase
}

func NewSegSync() *SegSync {
	return &SegSync{newSegRecBase(proto.PathMgmt_Which_segSync)}
}
