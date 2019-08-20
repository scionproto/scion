package util

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hiddenpath"
)

// GetRegistryMapping uses a greedy algorithm to approximate an optimal mapping
// from Registries to GroupIds such that all local Groups are mapped to the local
// Registry and the remaining Groups are mapped to a small number of remote Registries.
// The algorithm runs in O(Registries*Groups^2) and is at most ln(Groups)+1 times worse
// than an optimal solution.
func GetRegistryMapping(groups []*hiddenpath.Group, localIA addr.IA) (
	map[addr.IA][]hiddenpath.GroupId, error) {

	if err := findDuplicates(groups); err != nil {
		return nil, err
	}
	all := len(groups)
	count := 0
	mapping := map[addr.IA][]hiddenpath.GroupId{}
	covered := map[hiddenpath.GroupId]bool{}
	// prioritize local Registries
	for _, g := range groups {
		if g.HasRegistry(localIA) {
			mapping[localIA] = append(mapping[localIA], g.Id)
			covered[g.Id] = true
		}
	}
	count += len(mapping[localIA])
	for count < all {
		bestReg := addr.IA{}
		cover := map[addr.IA][]hiddenpath.GroupId{}
		// find Registry that can answer the most queries
		for _, g := range groups {
			if len(g.Registries) == 0 {
				return nil, common.NewBasicError("Group does not have any Registries",
					nil, "group", g.Id)
			}
			if covered[g.Id] {
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
			covered[g] = true
		}
		count += len(cover[bestReg])
	}
	return mapping, nil
}

func findDuplicates(groups []*hiddenpath.Group) error {
	var seen = map[hiddenpath.GroupId]bool{}
	for _, g := range groups {
		if seen[g.Id] {
			return common.NewBasicError("Provided Groups contain duplicates",
				nil, "group", g.Id)
		}
		seen[g.Id] = true
	}
	return nil
}
