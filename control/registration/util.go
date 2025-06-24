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

package registration

import (
	"sort"
	"strconv"
	"sync"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/private/segment/seghandler"
)

func summarizeStats(s seghandler.SegStats, b map[string]beacon.Beacon) *summary {
	sum := newSummary()
	for _, id := range append(s.InsertedSegs, s.UpdatedSegs...) {
		sum.AddSrc(b[id].Segment.FirstIA())
		sum.Inc()
	}
	return sum
}

type writerLabels struct {
	StartIA addr.IA
	Ingress uint16
	SegType string
	Result  string
}

func (l writerLabels) Expand() []string {
	return []string{
		"start_isd_as", l.StartIA.String(),
		"ingress_interface", strconv.Itoa(int(l.Ingress)),
		"seg_type", l.SegType,
		prom.LabelResult, l.Result,
	}
}

func (l writerLabels) WithResult(result string) writerLabels {
	l.Result = result
	return l
}

type summary struct {
	mu    sync.Mutex
	srcs  map[addr.IA]struct{}
	ifIDs map[uint16]struct{}
	count int
}

func newSummary() *summary {
	return &summary{
		srcs:  make(map[addr.IA]struct{}),
		ifIDs: make(map[uint16]struct{}),
	}
}

func (s *summary) AddSrc(ia addr.IA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.srcs[ia] = struct{}{}
}

func (s *summary) AddIfID(ifID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ifIDs[ifID] = struct{}{}
}

func (s *summary) Inc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
}

func (s *summary) IfIDs() []uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]uint16, 0, len(s.ifIDs))
	for ifID := range s.ifIDs {
		list = append(list, ifID)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}
