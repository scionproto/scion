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

package egress

import (
	"fmt"
	"math"
	"time"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

const pathFailExpiration = 5 * time.Minute

type sessPathPool map[pathmgr.PathKey]*sessPath

// Return the path with the fewest failures, excluding the current path (if specified).
func (spp sessPathPool) get(currKey pathmgr.PathKey) *sessPath {
	var sp *sessPath
	var minFail uint16 = math.MaxUint16
	for k, v := range spp {
		if k == currKey {
			// Exclude the current path, if specified.
			continue
		}
		if v.failCount < minFail {
			sp = v
			minFail = v.failCount
		}
	}
	return sp
}

func (spp sessPathPool) update(aps pathmgr.AppPathSet) {
	// Remove any old entries that aren't present in the update.
	for key := range spp {
		if _, ok := aps[key]; !ok {
			delete(spp, key)
		}
	}
	for key, ap := range aps {
		e, ok := spp[key]
		if !ok {
			// This is a new path, add an entry.
			spp[key] = newSessPath(key, ap.Entry)
		} else {
			// This path already exists, update it.
			e.pathEntry = ap.Entry
		}
	}
}

type sessPath struct {
	key       pathmgr.PathKey
	pathEntry *sciond.PathReplyEntry
	lastFail  time.Time
	failCount uint16
}

func newSessPath(key pathmgr.PathKey, pathEntry *sciond.PathReplyEntry) *sessPath {
	return &sessPath{key: key, pathEntry: pathEntry, lastFail: time.Now()}
}

func (sp *sessPath) fail() {
	sp.lastFail = time.Now()
	if sp.failCount < math.MaxInt16 {
		sp.failCount += 1
	}
}

func (sp *sessPath) expireFails() {
	if time.Since(sp.lastFail) > pathFailExpiration {
		sp.failCount /= 2
	}
}

func (sp *sessPath) String() string {
	return fmt.Sprintf("Key: %s %s lastFail: %s failCount: %d", sp.key,
		sp.pathEntry.Path, sp.lastFail, sp.failCount)
}
