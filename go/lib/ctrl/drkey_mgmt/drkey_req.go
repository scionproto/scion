// Copyright 2018 ETH Zurich
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

// This file contains the Go representation of Certificate Chain requests.

package drkey_mgmt

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*DRKeyReq)(nil)

type DRKeyReq struct {
	SrcIA   addr.IAInt `capnp:"isdas"`
	ValTime uint32
}

func (c *DRKeyReq) IA() addr.IA {
	return c.SrcIA.IA()
}

func (c *DRKeyReq) ProtoId() proto.ProtoIdType {
	return proto.DRKeyReq_TypeID
}

func (c *DRKeyReq) String() string {
	return fmt.Sprintf("Src ISD-AS: %s ValTime: %v",
		c.IA(), c.ValTime)
}
