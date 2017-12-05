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
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
)

const (
	// maximum number of queries that can fit in the watch queue
	queryChanCap uint64 = 1 << 10
	// the number of max paths requested in each SCIOND query
	numReqPaths = 5
	// time between reconnection attempts if SCIOND fails
	reconnectInterval = 3 * time.Second
	// wildcard filter key string
	matchAll = "*"
)

type IAKey struct {
	src addr.IAInt
	dst addr.IAInt
}

func (k IAKey) String() string {
	return fmt.Sprintf("%s.%s", k.src.IA(), k.dst.IA())
}

// A filterSet contains all the thread safe objects for a source and
// destination, indexed by their filter string. A filter string of "*" means no
// filtering is done, and is used to keep a collection of all available paths.
type filterSet map[string]*pathFilter

// update all the pathFilters in fs to contain the paths in aps that match
// their respective PathPredicates.
func (fs filterSet) update(aps AppPathSet) {
	// Walk each PathFilter in this FilterSet and Update paths if needed
	for _, pathFilter := range fs {
		pathFilter.update(aps)
	}
}

type pathFilter struct {
	sp       *SyncPaths
	pp       *PathPredicate
	refCount int
}

// update replaces the pathFilter's paths with those from aps, filtered by the
// pathFilter's PathPredicate (if set).
func (pf *pathFilter) update(aps AppPathSet) {
	// Filter the paths according to the current predicate
	newAPS := make(AppPathSet)
	if pf.pp == nil {
		newAPS = aps
	} else {
		for _, appPath := range aps {
			match := pf.pp.Eval(appPath.Entry)
			if match {
				newAPS.Add(appPath.Entry)
			}
		}
	}
	pf.sp.update(newAPS)
}
