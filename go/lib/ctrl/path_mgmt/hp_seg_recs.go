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
	"strings"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*HPSegRecs)(nil)

type HPSegRecs struct {
	GroupId *HPGroupId
	Recs    []*seg.Meta
	Err     string
}

func (hs *HPSegRecs) ProtoId() proto.ProtoIdType {
	return proto.HPSegRecs_TypeID
}

func (hs *HPSegRecs) String() string {
	desc := []string{fmt.Sprintf("ID: %v\n  segments:", hs.GroupId)}
	for _, m := range hs.Recs {
		desc = append(desc, "    "+m.Segment.String())
	}
	return strings.Join(desc, "\n")
}

// ParseRaw populates the non-capnp fields of s based on data from the raw
// capnp fields.
func (hs *HPSegRecs) ParseRaw() error {
	return nil
}

var _ proto.Cerealizable = (*HPSegReg)(nil)

type HPSegReg struct {
	*HPSegRecs
}
