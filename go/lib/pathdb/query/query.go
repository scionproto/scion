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

package query

import (
	"time"

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

func (h *HPCfgID) Equal(other *HPCfgID) bool {
	if h == nil || other == nil {
		return h == other
	}
	return h.IA.Equal(other.IA) && h.ID == other.ID
}

var NullHpCfgID = HPCfgID{IA: addr.IAInt(0).IA(), ID: 0}

type IntfSpec struct {
	IA   addr.IA
	IfID common.IFIDType
}

type Params struct {
	SegIDs        []common.RawBytes
	SegTypes      []proto.PathSegType
	HpCfgIDs      []*HPCfgID
	Intfs         []*IntfSpec
	StartsAt      []addr.IA
	EndsAt        []addr.IA
	MinLastUpdate *time.Time
}

type Result struct {
	Seg        *seg.PathSegment
	LastUpdate time.Time
	HpCfgIDs   []*HPCfgID
}

// ResultOrErr is either a result or an error.
type ResultOrErr struct {
	Result *Result
	Err    error
}

// Results is a type for convenience methods on a slice of Results.
type Results []*Result

// Segs returns the segments in the Results slice.
func (r Results) Segs() seg.Segments {
	segs := make(seg.Segments, len(r))
	for i, r := range r {
		segs[i] = r.Seg
	}
	return segs
}

// ByLastUpdate implements the sort.Interface to sort results by LastUpdate time stamp.
type ByLastUpdate Results

func (r ByLastUpdate) Len() int           { return len(r) }
func (r ByLastUpdate) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r ByLastUpdate) Less(i, j int) bool { return r[i].LastUpdate.Before(r[j].LastUpdate) }
