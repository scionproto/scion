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

// This file contains the Go representation of segment requests.

package path_mgmt

import (
	"fmt"

	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*SegReq)(nil)

type SegReq struct {
	RawSrcIA uint32 `capnp:"srcIA"`
	RawDstIA uint32 `capnp:"dstIA"`
	Flags    struct {
		Sibra     bool
		CacheOnly bool
	}
}

func (s *SegReq) SrcIA() *addr.ISD_AS {
	return addr.IAFromInt(int(s.RawSrcIA))
}

func (s *SegReq) DstIA() *addr.ISD_AS {
	return addr.IAFromInt(int(s.RawDstIA))
}

func (s *SegReq) ProtoId() proto.ProtoIdType {
	return proto.SegReq_TypeID
}

func (s *SegReq) ProtoType() fmt.Stringer {
	return proto.SCION_Which_ifid
}

func (s *SegReq) NewStruct(p interface{}) (capnp.Struct, *common.Error) {
	type valid interface {
		NewSegReq() (proto.SegReq, error)
	}
	parent, ok := p.(valid)
	if !ok {
		return capnp.Struct{}, common.NewError("Unsupported parent capnp type",
			"id", s.ProtoId(), "type", s.ProtoType(), "parent", fmt.Sprintf("%T", p))
	}
	n, err := parent.NewSegReq()
	if err != nil {
		return capnp.Struct{}, common.NewError("Error creating struct in parent capnp",
			"id", s.ProtoId(), "type", s.ProtoType(), "parent", p, "err", err)
	}
	return n.Struct, nil
}

func (s *SegReq) String() string {
	return fmt.Sprintf("SrcIA: %v, DstIA: %d, Flags: %v", s.SrcIA(), s.DstIA(), s.Flags)
}
