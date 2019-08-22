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

package hpsegreq

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hiddenpath"
)

// GroupInfo holds all information about hidden path groups needed by the HPS
// throughout its life cycle
type GroupInfo struct {
	LocalRegistry addr.IA
	Groups        map[hiddenpath.GroupId]*hiddenpath.Group
}

// GroupIdSet is a set of hidden path GroupIds
type GroupIdSet map[hiddenpath.GroupId]struct{}

// GroupIdsToSet converts a list of GroupIds to a GroupIdSet,
// ensuring no duplcates.
func GroupIdsToSet(ids []hiddenpath.GroupId) GroupIdSet {
	set := make(GroupIdSet, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

// GetRegistryMapping uses a greedy algorithm to approximate an optimal mapping
// from Registries to GroupIds such that all local Groups are mapped to the local
// Registry and the remaining Groups are mapped to a small number of remote Registries.
// The algorithm runs in O(Registries*Groups^2) and is at most ln(Groups)+1 times worse
// than an optimal solution.
func (gi *GroupInfo) GetRegistryMapping(ids GroupIdSet) (
	map[addr.IA][]hiddenpath.GroupId, error) {

	if err := gi.CheckIds(ids); err != nil {
		return nil, err
	}
	groups := make([]*hiddenpath.Group, 0, len(ids))
	mapping := map[addr.IA][]hiddenpath.GroupId{}
	for id := range ids {
		group := gi.Groups[id]
		if group.HasRegistry(gi.LocalRegistry) {
			mapping[gi.LocalRegistry] = append(mapping[gi.LocalRegistry], id)
		} else {
			groups = append(groups, group)
		}

	}
	covered := make(map[hiddenpath.GroupId]struct{}, len(groups))
	for len(covered) < len(groups) {
		bestReg := addr.IA{}
		cover := map[addr.IA][]hiddenpath.GroupId{}
		// find Registry that can answer the most queries
		for _, g := range groups {
			if _, ok := covered[g.Id]; ok {
				// this group is already covered and should not increase the counter
				continue
			}
			for _, r := range g.Registries {
				cover[r] = append(cover[r], g.Id)
				if len(cover[r]) > len(cover[bestReg]) {
					bestReg = r
				}
			}
		}
		// bestReg covers the most Ids
		// add this registry to the mapping and mark all its Ids as covered
		mapping[bestReg] = cover[bestReg]
		for _, g := range cover[bestReg] {
			covered[g] = struct{}{}
		}
	}
	return mapping, nil
}

// CheckIds checks that the provided Ids are known to the HPS and
// that all Ids have at least one Registry.
func (gi *GroupInfo) CheckIds(ids GroupIdSet) error {
	for id := range ids {
		group, ok := gi.Groups[id]
		if !ok {
			return common.NewBasicError("Unknown group",
				nil, "group", id)
		}
		if len(group.Registries) == 0 {
			return common.NewBasicError("Group does not have any Registries",
				nil, "group", id)
		}
	}
	return nil
}
