// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*SegRecs)(nil)

type SegRecs struct {
	Recs      []*seg.Meta
	SRevInfos []*SignedRevInfo
}

func (s *SegRecs) ProtoId() proto.ProtoIdType {
	return proto.SegRecs_TypeID
}

func (s *SegRecs) String() string {
	desc := []string{"segments:"}
	for _, m := range s.Recs {
		desc = append(desc, "  "+m.String())
	}
	if len(s.SRevInfos) > 0 {
		desc = append(desc, "revocations:")
		for _, info := range s.SRevInfos {
			desc = append(desc, "  "+info.String())
		}
	}
	return strings.Join(desc, "\n")
}

// ParseRaw populates the non-capnp fields of s based on data from the raw
// capnp fields.
func (s *SegRecs) ParseRaw() error {
	for i, segMeta := range s.Recs {
		if err := segMeta.Segment.ParseRaw(); err != nil {
			return common.NewBasicError("Unable to parse segment", err, "seg_index", i,
				"segment", segMeta.Segment)
		}
	}
	return nil
}

var _ proto.Cerealizable = (*SegReg)(nil)

type SegReg struct {
	*SegRecs
}

var _ proto.Cerealizable = (*SegSync)(nil)

type SegSync struct {
	*SegRecs
}
