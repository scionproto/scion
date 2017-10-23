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

// FIXME(scrye): make the cache expire old entries (including GC'ing resources).

package pathmgr

import (
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

type cacheEntry struct {
	// Set of currently available paths
	aps AppPathSet
	// Set of watched filters
	fs filterSet
	// Set to true if the paths are watched (i.e., periodically refreshed from SCIOND)
	registered bool
	// Time when paths were last changed
	timestamp time.Time
}

type cache struct {
	mutex sync.Mutex
	// Keep one entry for each src-dst pair
	m map[IAKey]*cacheEntry
	// When an app reads a path older than maxAge, SCIOND is requeried to get fresh paths
	maxAge time.Duration
	// Revocation table mapping uifid to paths that contain the uifid
	revTable *revTable
}

func newCache(maxAge time.Duration) *cache {
	return &cache{
		m:        make(map[IAKey]*cacheEntry),
		maxAge:   maxAge,
		revTable: newRevTable(),
	}
}

// getAPS returns the paths between src and dst. If the paths are stale or
// missing, the second return value is false.
func (c *cache) getAPS(src, dst *addr.ISD_AS) (AppPathSet, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if entry, ok := c.getEntry(src, dst); ok {
		if time.Now().Sub(entry.timestamp) > c.maxAge || len(entry.aps) == 0 {
			// Paths are missing or stale, caller should ask the resolver to do a blocking request
			return nil, false
		}
		return entry.aps, true
	}
	return nil, false
}

// watch adds periodic lookups for paths between src and dst.
func (c *cache) watch(src, dst *addr.ISD_AS) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.getEntry(src, dst)
	if !ok {
		entry = c.addEntry(src, dst)
	}
	if !entry.registered {
		entry.registered = true
		pf := &pathFilter{
			sp: NewSyncPaths(),
		}
		entry.fs["*"] = pf
	}
}

// isWatched returns true if src and dst are registered for periodic lookups.
func (c *cache) isWatched(src, dst *addr.ISD_AS) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if entry, ok := c.getEntry(src, dst); ok {
		return entry.registered
	}
	return false
}

// getSP returns a pointer to a thread-safe object that contains paths between
// src and dst. The object is shared between callers, so callers must never
// write to it.
func (c *cache) getSP(src, dst *addr.ISD_AS) (*SyncPaths, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if entry, ok := c.getEntry(src, dst); ok {
		fs, ok := entry.fs["*"]
		return fs.sp, ok
	}
	return nil, false
}

// addFilteredSP adds periodic lookups for paths between src and dst, filtered
// according to filter.
func (c *cache) addFilteredSP(src, dst *addr.ISD_AS, filter *PathPredicate) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if entry, ok := c.getEntry(src, dst); ok {
		if !entry.registered {
			return common.NewCError("Unable to add path filter, src and dst are not registered",
				"src", src, "dst", dst)
		}
		pf := &pathFilter{
			sp: NewSyncPaths(),
			pp: filter,
		}
		pf.update(entry.aps)
		entry.fs[filter.String()] = pf
	}
	return common.NewCError("Unable to add path filter, src and dst are not registered",
		"src", src, "dst", dst)
}

// getFilteredSP returns a pointer to a thread-safe object that contains paths
// between src and dst, filtered according to filter. The object is shared
// between callers, so callers must never write to it.
func (c *cache) getFilteredSP(src, dst *addr.ISD_AS, filter *PathPredicate) (*SyncPaths, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if entry, ok := c.getEntry(src, dst); ok {
		if pf, ok := entry.fs[filter.String()]; ok {
			return pf.sp, true
		}
	}
	return nil, false
}

// update the set of paths between src and dst to aps.
func (c *cache) update(src, dst *addr.ISD_AS, aps AppPathSet) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.getEntry(src, dst)
	if !ok {
		entry = c.addEntry(src, dst)
	}
	entry.aps = aps
	// Update all watches
	entry.fs.update(entry.aps)
	// Update revocation lists
	c.revTable.updatePathSet(aps)
	entry.timestamp = time.Now()
}

// remove one path from the set of paths between src and dst.
func (c *cache) remove(src, dst *addr.ISD_AS, ap *AppPath) {
	entry, ok := c.getEntry(src, dst)
	if !ok {
		log.Warn("Attempted to revoke known path, but no path set found", "path",
			ap, "src", src, "dst", dst)
		return
	}
	delete(entry.aps, ap.Key())
	// Update all watches
	for _, pf := range entry.fs {
		pf.update(entry.aps)
	}
}

// revoke all paths containing uifid from the cache.
func (c *cache) revoke(u uifid) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	aps := c.revTable.revoke(u)
	for _, ap := range aps {
		src := ap.Entry.Path.SrcIA()
		dst := ap.Entry.Path.DstIA()
		if src == nil || dst == nil {
			continue
		}
		c.remove(src, dst, ap)
	}
}

// getEntry (internal) retrieves the cache entry for src and dst.
func (c *cache) getEntry(src, dst *addr.ISD_AS) (*cacheEntry, bool) {
	k := IAKey{src: src.IAInt(), dst: dst.IAInt()}
	entry, ok := c.m[k]
	return entry, ok
}

// addEntry (internal) initializes a cache entry for src and dst.
func (c *cache) addEntry(src, dst *addr.ISD_AS) *cacheEntry {
	entry := &cacheEntry{
		aps:       make(AppPathSet),
		fs:        make(filterSet),
		timestamp: time.Now(),
	}
	k := IAKey{src: src.IAInt(), dst: dst.IAInt()}
	c.m[k] = entry
	return entry
}
