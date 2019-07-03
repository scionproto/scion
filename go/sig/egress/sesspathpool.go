// Copyright 2018 ETH Zurich
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
	"math"
	"time"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

const pathFailExpiration = 5 * time.Minute

type SessPathPool map[spathmeta.PathKey]*SessPathStats

func NewSessPathPool() *SessPathPool {
	return &SessPathPool{}
}

// Get returns the most suitable path. Excludes a specific path, if possible.
func (spp SessPathPool) Get(exclude spathmeta.PathKey) *SessPath {
	var bestSessPath *SessPathStats
	var minFail uint16 = math.MaxUint16
	var bestNonExpiringSessPath *SessPathStats
	var minNonExpiringFail uint16 = math.MaxUint16
	for k, v := range spp {
		if k == exclude {
			continue
		}
		if v.failCount < minFail {
			bestSessPath = v
			minFail = v.failCount
		}
		if v.failCount < minNonExpiringFail && !v.SessPath.IsCloseToExpiry() {
			bestNonExpiringSessPath = v
			minNonExpiringFail = v.failCount
		}
	}
	// Return a non-expiring path with least failures.
	if bestNonExpiringSessPath != nil {
		return bestNonExpiringSessPath.SessPath
	}
	// If not possible, return the best path that's close to expiry.
	if bestSessPath != nil {
		return bestSessPath.SessPath
	}
	// In the worst case return the excluded path. Given that the caller asked to exclude it
	// it's probably non-functional, but it's the only option we have.
	res := spp[exclude]
	if res == nil {
		return nil
	}
	return res.SessPath
}

func (spp SessPathPool) GetByKey(key spathmeta.PathKey) *SessPath {
	res := spp[key]
	if res == nil {
		return nil
	}
	return res.SessPath
}

func (spp SessPathPool) Update(aps spathmeta.AppPathSet) {
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
			spp[key] = NewSessPathStats(key, ap.Entry)
		} else {
			// This path already exists, update it.
			e.SessPath.pathEntry = ap.Entry
		}
	}
}

// Reply is called when a probe reply arrives.
// 'sent' is the time when the original probe was sent.
func (spp SessPathPool) Reply(path *SessPath, sent time.Time) {
}

// Timeout is called when a reply to a probe is not received in time.
// 'sent' is the time when the original probe was sent.
func (spp SessPathPool) Timeout(path *SessPath, sent time.Time) {
	sp := spp[path.Key()]
	if sp == nil {
		return
	}
	sp.lastFail = time.Now()
	if sp.failCount < math.MaxInt16 {
		sp.failCount += 1
	}
}

func (spp SessPathPool) ExpireFails() {
	for _, sp := range spp {
		if time.Since(sp.lastFail) > pathFailExpiration {
			sp.failCount /= 2
		}
	}
}

type SessPathStats struct {
	SessPath  *SessPath
	lastFail  time.Time
	failCount uint16
}

func NewSessPathStats(key spathmeta.PathKey, pathEntry *sciond.PathReplyEntry) *SessPathStats {
	return &SessPathStats{
		SessPath: NewSessPath(key, pathEntry),
		lastFail: time.Now(),
	}
}
