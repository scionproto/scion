// Copyright 2025 Anapaya Systems
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

package segreg

import (
	"sort"
	"sync"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/segment/seghandler"
)

type RegistrationSummary struct {
	mu    sync.Mutex
	srcs  map[addr.IA]struct{}
	ifIDs map[uint16]struct{}
	count int
}

func NewSummary() *RegistrationSummary {
	return &RegistrationSummary{
		srcs:  make(map[addr.IA]struct{}),
		ifIDs: make(map[uint16]struct{}),
	}
}

func (s *RegistrationSummary) RecordBeacon(beacon *beacon.Beacon) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.srcs[beacon.Segment.FirstIA()] = struct{}{}
	s.count++
	if beacon.InIfID != 0 {
		s.ifIDs[beacon.InIfID] = struct{}{}
	}
}

func (s *RegistrationSummary) RecordSegment(segment *seg.PathSegment) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.srcs[segment.FirstIA()] = struct{}{}
	s.count++
}

func (s *RegistrationSummary) GetCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.count
}

func (s *RegistrationSummary) GetSrcs() map[addr.IA]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	srcs := make(map[addr.IA]struct{})
	for src := range s.srcs {
		srcs[src] = struct{}{}
	}
	return srcs
}

func (s *RegistrationSummary) GetIfIDs() []uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()

	list := make([]uint16, 0, len(s.ifIDs))
	for ifID := range s.ifIDs {
		list = append(list, ifID)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}

func SummarizeSegStats(s seghandler.SegStats, b map[string]beacon.Beacon) *RegistrationSummary {
	sum := NewSummary()
	for _, id := range append(s.InsertedSegs, s.UpdatedSegs...) {
		sum.RecordSegment(b[id].Segment)
	}
	return sum
}
