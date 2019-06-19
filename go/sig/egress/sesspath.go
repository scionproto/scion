// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

const (
	pathFailExpiration = 5 * time.Minute
	// The interval used to compute path statistics (median latency and such).
	// This number should not be too low - it could result in rapid path flapping.
	// It shouldn't be too high either - metric policies would then take longer to kick in.
	statInterval = 60 * time.Second
)

type SessPathPool map[spathmeta.PathKey]*SessPath

// Return the most suitable path. Exclude a specific path, if possible.
func (spp SessPathPool) Get(exclude spathmeta.PathKey) *SessPath {
	var bestSessPath *SessPath
	var minFail uint16 = math.MaxUint16
	var bestNonExpiringSessPath *SessPath
	var minNonExpiringFail uint16 = math.MaxUint16
	for k, v := range spp {
		if k == exclude {
			continue
		}
		if v.failCount < minFail {
			bestSessPath = v
			minFail = v.failCount
		}
		if v.failCount < minNonExpiringFail && !v.IsCloseToExpiry() {
			bestNonExpiringSessPath = v
			minNonExpiringFail = v.failCount
		}
	}
	// Return a non-expiring path with least failures.
	if bestNonExpiringSessPath != nil {
		return bestNonExpiringSessPath
	}
	// If not possible, return the best path that's close to expiry.
	if bestSessPath != nil {
		return bestSessPath
	}
	// In the worst case return the excluded path. Given that the caller asked to exclude it
	// it's probably non-functional, but it's the only option we have.
	return spp[exclude]
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
			spp[key] = NewSessPath(key, ap.Entry)
		} else {
			// This path already exists, update it.
			e.pathEntry = ap.Entry
		}
	}
}

type Probe struct {
	sent     time.Time
	received *time.Time
}

type SessPathStats struct {
	// Median latency.
	Latency time.Duration
	// Max latency - median latency.
	Jitter time.Duration
	// Perecentage of dropped probes from interval (0, 1).
	DropRate float64
}

// A SessPath contains a path and metadata related to path health.
type SessPath struct {
	key       spathmeta.PathKey
	pathEntry *sciond.PathReplyEntry
	lastFail  time.Time
	failCount uint16
	// Path metric-related stuff.
	probes []Probe
	stats  SessPathStats
}

func NewSessPath(key spathmeta.PathKey, pathEntry *sciond.PathReplyEntry) *SessPath {
	sp := SessPath{
		key:       key,
		pathEntry: pathEntry,
		lastFail:  time.Now(),
		probes:    make([]Probe, 0),
	}
	sp.updateStats(nil, nil, time.Now())
	return &sp
}

func (sp *SessPath) Key() spathmeta.PathKey {
	return sp.key
}

func (sp *SessPath) PathEntry() *sciond.PathReplyEntry {
	return sp.pathEntry
}

func (sp *SessPath) IsCloseToExpiry() bool {
	return sp.PathEntry().Path.Expiry().Before(time.Now().Add(SafetyInterval))
}

func (sp *SessPath) Reply(sent time.Time) {
	now := time.Now()
	sp.updateStats(&sent, &now, now)
}

func (sp *SessPath) Timeout(sent time.Time) {
	now := time.Now()
	sp.lastFail = now
	if sp.failCount < math.MaxInt16 {
		sp.failCount += 1
	}
	sp.updateStats(&sent, nil, now)
}

// Update the new path statistics.
// Set sent to nil in case you want the statistics to be recomputed without adding a new datapoint.
// Set received to nil if the heartbeat to the peer timed out.
// The algorithm implements backfill (even probes already classified as dropped
// can be changed to non-dropped if the reply arrives late).
// The reasoning is that having more relevant info (e.g. latencies over 1/2 sec)
// is worth more than being entirely consistent.
func (sp *SessPath) updateStats(sent *time.Time, received *time.Time, now time.Time) {
	// Get rid of the old irrelevant probes points.
	backfill := false
	cutoff := now.Add(-statInterval)
	probes := sp.probes
	sp.probes = make([]Probe, 0)
	for _, probe := range probes {
		if probe.sent.After(cutoff) {
			if sent != nil && probe.received == nil && probe.sent == *sent {
				probe.received = received
				backfill = true
			}
			sp.probes = append(sp.probes, probe)
		}
	}
	// Add the new probe.
	if sent != nil && !backfill {
		sp.probes = append(sp.probes, Probe{sent: *sent, received: received})
	}
	// Make an ordered list of latencies.
	drops := 0
	latencies := make([]time.Duration, 0)
	for _, probe := range sp.probes {
		if probe.received == nil {
			drops += 1
			continue
		}
		latencies = append(latencies, probe.received.Sub(probe.sent))
	}
	sort.Slice(latencies, func(x, y int) bool { return latencies[x] < latencies[y] })
	if len(latencies) == 0 {
		// 100% of drops
		sp.stats.Latency = 0
		sp.stats.Jitter = 0
		sp.stats.DropRate = 1.0
	} else {
		max := latencies[len(latencies)-1]
		median := latencies[len(latencies)/2]
		sp.stats.Latency = median
		sp.stats.Jitter = max - median
		sp.stats.DropRate = float64(drops) / float64(len(sp.probes))
	}
}

func (sp *SessPath) Stats() SessPathStats {
	// Recompute statistics - some probes may already be stale.
	sp.updateStats(nil, nil, time.Now())
	return sp.stats
}

func (sp *SessPath) ExpireFails() {
	if time.Since(sp.lastFail) > pathFailExpiration {
		sp.failCount /= 2
	}
}

func (sp *SessPath) String() string {
	return fmt.Sprintf("Key: %s %s lastFail: %s failCount: %d", sp.key,
		sp.pathEntry.Path, sp.lastFail, sp.failCount)
}
