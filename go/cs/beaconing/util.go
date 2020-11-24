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

package beaconing

import (
	"sort"
	"sync"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology"
)

// sortedIntfs returns all interfaces of the given link type sorted by interface
// ID.
func sortedIntfs(intfs *ifstate.Interfaces, linkType topology.LinkType) []common.IFIDType {

	var result []common.IFIDType
	for ifid, intf := range intfs.All() {
		topoInfo := intf.TopoInfo()
		if topoInfo.LinkType != linkType {
			continue
		}
		result = append(result, ifid)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

type summary struct {
	mu    sync.Mutex
	srcs  map[addr.IA]struct{}
	ifIds map[common.IFIDType]struct{}
	count int
}

func newSummary() *summary {
	return &summary{
		srcs:  make(map[addr.IA]struct{}),
		ifIds: make(map[common.IFIDType]struct{}),
	}
}

func (s *summary) AddSrc(ia addr.IA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.srcs[ia] = struct{}{}
}

func (s *summary) AddIfid(ifid common.IFIDType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ifIds[ifid] = struct{}{}
}

func (s *summary) Inc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
}

func (s *summary) IfIds() []common.IFIDType {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]common.IFIDType, 0, len(s.ifIds))
	for ifId := range s.ifIds {
		list = append(list, ifId)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}

type ctr struct {
	sync.Mutex
	c int
}

func (c *ctr) Inc() {
	c.Lock()
	defer c.Unlock()
	c.c++
}
