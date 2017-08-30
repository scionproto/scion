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

// This file contains the Go representation of an IFID packet

package ifid

import (
	"fmt"

	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*IFID)(nil)

type IFID struct {
	OrigIfID  uint64 `capnp:"origIF"`
	RelayIfID uint64 `capnp:"relayIF"`
}

func (i *IFID) ProtoId() proto.ProtoIdType {
	return proto.IFID_TypeID
}

func (i *IFID) ProtoType() fmt.Stringer {
	return proto.SCION_Which_ifid
}

func (i *IFID) NewStruct(p interface{}) (capnp.Struct, *common.Error) {
	type valid interface {
		NewIfid() (proto.IFID, error)
	}
	parent, ok := p.(valid)
	if !ok {
		return capnp.Struct{}, common.NewError("Unsupported parent capnp type",
			"id", i.ProtoId(), "type", i.ProtoType(), "parent", fmt.Sprintf("%T", p))
	}
	n, err := parent.NewIfid()
	if err != nil {
		return capnp.Struct{}, common.NewError("Error creating struct in parent capnp",
			"id", i.ProtoId(), "type", i.ProtoType(), "parent", p, "err", err)
	}
	return n.Struct, nil
}

func (i *IFID) String() string {
	return fmt.Sprintf("OrigIfID: %d, RelayIfID: %d", i.OrigIfID, i.RelayIfID)
}
