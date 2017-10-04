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

package pathmgr

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/class"
)

// Key is the string descriptor of the PathPredicate embedded
//
// FilterMap is not safe for concurrent use.
type FilterMap map[string]FilterSet

func (fm FilterMap) Get(src, dst *addr.ISD_AS, pp *class.PathPredicate) (*SyncPaths, bool) {
	key := IAKey(src, dst)
	filterSet, ok := fm[key]
	if !ok {
		return nil, false
	}

	pathFilter, ok := filterSet[pp.String()]
	if !ok {
		return nil, false
	}
	return pathFilter.sp, true
}

func (fm FilterMap) Set(src, dst *addr.ISD_AS, pp *class.PathPredicate) *SyncPaths {
	var filterSet FilterSet
	key := IAKey(src, dst)

	// If set not already initialized for this src-dst pair, initialize it now
	filterSet, ok := fm[key]
	if !ok {
		filterSet = make(FilterSet)
		fm[key] = filterSet
	}

	// If path filter is not registered yet, initialize it. Otherwise return
	// already existing SyncPaths.
	pathFilter, ok := filterSet[pp.String()]
	if !ok {
		pathFilter = &PathFilter{
			sp: NewSyncPaths(),
			pp: pp,
		}
		filterSet[pp.String()] = pathFilter
	}
	return pathFilter.sp
}

func (fm FilterMap) Update(src, dst *addr.ISD_AS, aps AppPathSet) {
	key := IAKey(src, dst)
	filterSet, ok := fm[key]
	if !ok {
		// Nothing to do, no src-dst pair registered yet
		return
	}

	// Walk each PathFilter in this FilterSet and Update paths if needed
	for _, pathFilter := range filterSet {
		// Filter the paths according to the current predicate
		newAPS := make(AppPathSet)
		for _, appPath := range aps {
			match := pathFilter.pp.Eval(appPath.Entry)
			if match {
				appPath.DuplicateIn(newAPS)
			}
		}

		// Check whether the paths need to be updated by computing the
		// symmetric difference between the current path set and the new path
		// set.
		currentAPS := pathFilter.sp.Load()
		toAdd := difference(newAPS, currentAPS)
		toRemove := difference(currentAPS, newAPS)
		if len(toAdd) > 0 || len(toRemove) > 0 {
			// Some paths have changed, replace the old set with the new set
			if len(newAPS) == 0 {
				// Use nil map instead of empty map for consistency with Get
				pathFilter.sp.Store(AppPathSet(nil))
			} else {
				pathFilter.sp.Store(newAPS)
			}
		}
	}
}

type FilterSet map[string]*PathFilter

type PathFilter struct {
	sp *SyncPaths
	pp *class.PathPredicate
}

func difference(x, y AppPathSet) AppPathSet {
	result := make(AppPathSet)
	for _, ap := range x {
		if _, ok := y[ap.Key()]; !ok {
			ap.DuplicateIn(result)
		}
	}
	return result
}
