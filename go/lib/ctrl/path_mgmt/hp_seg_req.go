// Copyright 2019 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*HPSegReq)(nil)

type HPSegReq struct {
	RawDstIA addr.IAInt `capnp:"dstIA"`
	GroupIds []*HPGroupId
}

func (s *HPSegReq) DstIA() addr.IA {
	return s.RawDstIA.IA()
}

func (s *HPSegReq) ProtoId() proto.ProtoIdType {
	return proto.HPSegReq_TypeID
}

func (s *HPSegReq) String() string {
	return fmt.Sprintf("Dst: %s, GroupIds: %v", s.DstIA(), s.GroupIds)
}
