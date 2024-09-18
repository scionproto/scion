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
	"bytes"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
)

type IntfSpec struct {
	IA   addr.IA
	IfID iface.ID
}

type Params struct {
	SegIDs     [][]byte
	SegTypes   []seg.Type
	HPGroupIDs []uint64
	Intfs      []*IntfSpec
	StartsAt   []addr.IA
	EndsAt     []addr.IA
}

type Result struct {
	Seg        *seg.PathSegment
	LastUpdate time.Time
	HPGroupIDs []uint64
	Type       seg.Type
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

// SegMetas returns the segments in a seg.Meta slice, i.e. returns the segments
// with their PathSegTypes.
func (r Results) SegMetas() []*seg.Meta {
	segs := make([]*seg.Meta, len(r))
	for i, r := range r {
		segs[i] = &seg.Meta{
			Type:    r.Type,
			Segment: r.Seg,
		}
	}
	return segs
}

// Len returns the number of results.
func (r Results) Len() int {
	return len(r)
}

// Less returns if seg[i] is less than seg[j] based on start_isd_as > end_isd_as > length > id
func (r Results) Less(i, j int) bool {
	firstA, lastA := r[i].Seg.FirstIA(), r[i].Seg.LastIA()
	firstB, lastB := r[j].Seg.FirstIA(), r[j].Seg.LastIA()
	lenA, lenB := len(r[i].Seg.ASEntries), len(r[j].Seg.ASEntries)
	switch {
	case firstA != firstB:
		return firstA < firstB
	case lastA != lastB:
		return lastA < lastB
	case lenA != lenB:
		return lenA < lenB
	default:
		return bytes.Compare(r[i].Seg.ID(), r[j].Seg.ID()) == -1
	}
}

// Swap swaps the two elements of Results
func (r Results) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

// ByLastUpdate implements the sort.Interface to sort results by LastUpdate time stamp.
type ByLastUpdate Results

func (r ByLastUpdate) Len() int           { return len(r) }
func (r ByLastUpdate) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r ByLastUpdate) Less(i, j int) bool { return r[i].LastUpdate.Before(r[j].LastUpdate) }
