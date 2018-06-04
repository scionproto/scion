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

package drkey

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

type union struct {
	Which    proto.DRKeyMgmt_Which
	DRKeyReq *DRKeyReq `capnp:"DRKeyReq"`
	DRKeyRep *DRKeyRep `capnp:"DRKeyRep"`
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *DRKeyReq:
		u.Which = proto.DRKeyMgmt_Which_drkeyReq
		u.DRKeyReq = p
	case *DRKeyRep:
		u.Which = proto.DRKeyMgmt_Which_drkeyRep
		u.DRKeyRep = p
	default:
		return common.NewBasicError("Unsupported drkey mgmt union type (set)", nil,
			"type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.DRKeyMgmt_Which_drkeyReq:
		return u.DRKeyReq, nil
	case proto.DRKeyMgmt_Which_drkeyRep:
		return u.DRKeyRep, nil
	}
	return nil, common.NewBasicError("Unsupported drkey mgmt union type (get)", nil, "type", u.Which)
}
