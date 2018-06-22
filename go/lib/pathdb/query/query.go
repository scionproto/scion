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

package query

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)

// TODO(shitz): This should be moved when we have hidden path sets.
type HPCfgID struct {
	IA addr.IA
	ID uint64
}

func (h *HPCfgID) Eq(other *HPCfgID) bool {
	return h.IA.Eq(other.IA) && h.ID == other.ID
}

var NullHpCfgID = HPCfgID{IA: addr.IAInt(0).IA(), ID: 0}

type IntfSpec struct {
	IA   addr.IA
	IfID uint64
}

type Params struct {
	SegID    common.RawBytes
	SegTypes []proto.PathSegType
	HpCfgIDs []*HPCfgID
	Intfs    []*IntfSpec
	StartsAt []addr.IA
	EndsAt   []addr.IA
}

type Result struct {
	Seg      *seg.PathSegment
	HpCfgIDs []*HPCfgID
}
