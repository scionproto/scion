// Copyright 2019 Anapaya Systems
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

package readonly

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/spath"
)

// Beacon contains a validated read-only path segment and the ingress
// interface id.
type Beacon struct {
	Segment Segment
	InIfId  common.IFIDType
	IA      addr.IA
}

// Segment is a read-only wrapper for PathSegment to avoid awkward error
// handling for already validated data. The embedded segment must not be
// modified or the code is allowed to panic.
type Segment struct {
	*seg.PathSegment
}

// NewSegment validates, sets the Ids and creates a read-only wrapper for
// the provided segment. After this call, the segment must not be modified.
func NewSegment(s *seg.PathSegment) (Segment, error) {
	if err := s.Validate(); err != nil {
		return Segment{}, err
	}
	return segWithIdsSet(s)
}

// NewSegmentFromRaw validates, sets the Ids and creates a read-only
// wrapper for the parsed segment. After this call, the segment must not be
// modified.
func NewSegmentFromRaw(b common.RawBytes) (Segment, error) {
	s, err := seg.NewSegFromRaw(b)
	if err != nil {
		return Segment{}, err
	}
	return segWithIdsSet(s)
}

// WritableSegment returns a copy of the segment that is writeable.
func (s Segment) WritableSegment() (*seg.PathSegment, error) {
	packed, err := s.PathSegment.Pack()
	if err != nil {
		return nil, err
	}
	return seg.NewSegFromRaw(packed)
}

// ID returns the id. If the segment has been modified after construction,
// this call might panic.
func (s Segment) ID() common.RawBytes {
	id, err := s.PathSegment.ID()
	if err != nil {
		panic(fmt.Sprintf("Modified read-only segment ID err=%s", err))
	}
	return id
}

// FullId returns the full id. If the segment has been modified after
// construction this call might panic.
func (s Segment) FullId() common.RawBytes {
	id, err := s.PathSegment.FullId()
	if err != nil {
		panic(fmt.Sprintf("Modified read-only segment FullId err=%s", err))
	}
	return id
}

// InfoF returns the info field. If the segment has been modified after
// construction, this might panic.
func (s Segment) InfoF() *spath.InfoField {
	info, err := s.PathSegment.InfoF()
	if err != nil {
		panic(fmt.Sprintf("Modified read-only segment Info err=%s", err))
	}
	return info
}

// AddASEntry panics always. It shall not be called.
func (s Segment) AddASEntry() {
	panic("Must not modify read-only segment")
}

func segWithIdsSet(s *seg.PathSegment) (Segment, error) {
	if _, err := s.ID(); err != nil {
		return Segment{}, common.NewBasicError("Unable calculate ID", err)
	}
	if _, err := s.FullId(); err != nil {
		return Segment{}, common.NewBasicError("Unable calculate FullID", err)
	}
	return Segment{s}, nil
}
