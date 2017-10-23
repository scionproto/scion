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
)

// filterMap maps iaKey(src, dst) to a filterSet, which is itself a map from a
// string description of a path predicate to a *SyncPaths object. This allows
// us to keep multiple active filters for the same source and destination ASes.
// External code needs to call update on path changes (e.g., new replies from
// SCIOND and revocations).
//
// filterMap is not safe for concurrent use.
type filterMap map[string]filterSet

// get returns the *SyncPaths object for source src, destination dst and path filter pp.
// If the entry does not exist, the second returned value is false.
func (fm filterMap) get(src, dst *addr.ISD_AS, pp *PathPredicate) (*SyncPaths, bool) {
	key := iaKey(src, dst)
	filterSet, ok := fm[key]
	if !ok {
		return nil, false
	}

	// FIXME(scrye): multiple callers might register the same path predicate;
	// if one of them decides to unregister the predicate, it would remove it
	// for all callers. Fix this to take unique instances into account (e.g.,
	// via names or reference counting)
	pathFilter, ok := filterSet[pp.String()]
	if !ok {
		return nil, false
	}
	return pathFilter.sp, true
}

// set initializes a new *SyncPaths object for source src, destination dst and
// path filter pp.  If one already exists, a reference to the existing one is
// returned.  Path resolver code can use this object to store up-to-date paths
// within it, and further expose it to user applications that want up-to-date
// paths satisfying predicate pp.
func (fm filterMap) set(src, dst *addr.ISD_AS, pp *PathPredicate) *SyncPaths {
	var fs filterSet
	key := iaKey(src, dst)

	// If set not already initialized for this src-dst pair, initialize it now
	fs, ok := fm[key]
	if !ok {
		fs = make(filterSet)
		fm[key] = fs
	}

	// If path filter is not registered yet, initialize it. Otherwise return
	// already existing SyncPaths.
	pf, ok := fs[pp.String()]
	if !ok {
		pf = &pathFilter{
			sp: NewSyncPaths(),
			pp: pp,
		}
		fs[pp.String()] = pf
	}
	return pf.sp
}

// update goes through all filters registered between src and dst, detects
// whether paths have changed and, if necessary, updates the *SyncPaths
func (fm filterMap) update(src, dst *addr.ISD_AS, aps AppPathSet) {
	key := iaKey(src, dst)
	filterSet, ok := fm[key]
	if !ok {
		// Nothing to do, no src-dst pair registered yet
		return
	}

	filterSet.update(aps)
}

type filterSet map[string]*pathFilter

// Function update changes all the pathFilters in fs to contain the paths in
// aps that match their respective PathPredicates.
func (fs filterSet) update(aps AppPathSet) {
	// Walk each PathFilter in this FilterSet and Update paths if needed
	for _, pathFilter := range fs {
		pathFilter.update(aps)
	}
}

type pathFilter struct {
	sp *SyncPaths
	pp *PathPredicate
}

// Function update changes paths within the SyncPaths object of pf to the ones
// in aps that match the PathPredicate in pf.
func (pf *pathFilter) update(aps AppPathSet) {
	// Filter the paths according to the current predicate
	newAPS := make(AppPathSet)
	for _, appPath := range aps {
		match := pf.pp.Eval(appPath.Entry)
		if match {
			appPath.duplicateIn(newAPS)
		}
	}
	pf.sp.update(newAPS)
}
