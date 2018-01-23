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
	"strings"

	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*SegRecs)(nil)

type SegRecs struct {
	Recs     []*seg.Meta
	RevInfos []*RevInfo
}

func (s *SegRecs) ProtoId() proto.ProtoIdType {
	return proto.SegRecs_TypeID
}

func (s *SegRecs) String() string {
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

var _ proto.Cerealizable = (*SegReply)(nil)

type SegReply struct {
	*SegRecs
}

var _ proto.Cerealizable = (*SegReg)(nil)

type SegReg struct {
	*SegRecs
}

var _ proto.Cerealizable = (*SegSync)(nil)

type SegSync struct {
	*SegRecs
}
