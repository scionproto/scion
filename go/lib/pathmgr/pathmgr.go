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

// Package pathmgr implement an asynchronous Path Resolver for SCION Paths.
//
// A new resolver can be instantiated by calling `New`. There are two types of
// supported path queries, simple and via continuous updates.
//
// Simple path queries are issued via 'Query'; they return a slice of valid
// paths.
//
// Continuous update path queries are added via 'Register', which returns a
// thread-safe pointer to a slice of paths; if no valid paths exist the slice
// is empty. Access to the underlying slice is obtained by calling `Load` on
// the pointer.  When updating paths, the resolver will atomically change the
// value of the pointer to point to a new slice of paths. Fresh paths can be
// obtained by calling Load again.
//
// An example of how this package can be used can be found in the associated
// test file.
//
// If the connection to SCIOND fails, the resolver automatically attempts to
// reestablish the connection. During this period, paths are not expired. Paths
// will be transparently refreshed after reconnecting to SCIOND.
package pathmgr

import (
	"fmt"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	cache "github.com/patrickmn/go-cache"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

var (
	// Time between checks for stale path references
	pathCleanupInterval = time.Minute
	// TTL for pointers to Path Resolver cached paths
	pathTTL = 30 * time.Minute
)

type PR struct {
	// Lookup, reconnect and Register acquire this lock as separate goroutines
	sync.Mutex
	sciondPath string
	sciond     *sciond.Connector
	// Path map for continuously updated queries
	regMap map[string]*SyncPaths
	// Path cache for simple queries
	pathMap *cache.Cache
	// Number of IAs registered for priority tracking
	regCount uint64
	// Used for keeping track of which queries need to be sent
	queries chan query
	// State of SCIOND connection
	state sciondState
	// Duration between two path lookups for a registered path
	refireInterval time.Duration
	// Cached paths indexed by UIFID for revocations
	revTableCache *revTable
	// Continuously updated paths indexed by UIFID
	revTableReg *revTable
	log.Logger
}

// New connects to SCIOND and spawns the asynchronous path resolver. New
// returns with an error if a connection to SCIOND could not be established.
func New(sciondPath string, refireInterval time.Duration, logger log.Logger) (*PR, error) {
	// Connect to sciond
	sciondSock, err := sciond.Connect(sciondPath)
	if err != nil {
		// Let external code handle initial failure
		return nil, common.NewCError("Unable to connect to SCIOND", "err", err)
	}

	pr := &PR{
		sciondPath:     sciondPath,
		sciond:         sciondSock,
		state:          sciondUp,
		regMap:         make(map[string]*SyncPaths),
		queries:        make(chan query, queryChanCap),
		refireInterval: refireInterval,
		pathMap:        cache.New(pathTTL, pathCleanupInterval),
		revTableCache:  newRevTable(),
		revTableReg:    newRevTable(),
		Logger:         logger.New("pathmgr")}

	// Start resolver, which periodically refreshes paths for registered
	// destinations
	go pr.resolver()
	return pr, nil
}

// Query returns a slice of paths between src and dst. If the paths are not
// found in the path resolver's cache, a query to SCIOND is issued and the
// function blocks until the reply is received.
func (r *PR) Query(src, dst *addr.ISD_AS) AppPathSet {
	r.Lock()
	defer r.Unlock()

	// Check if srcIA-dstIA registered with path resolver
	iaKey := IAKey(src, dst)
	pathSetI, ok := r.pathMap.Get(iaKey)
	if ok {
		return pathSetI.(AppPathSet)
	}

	// We don't have a cached path list, so we ask SCIOND
	q := query{src: src, dst: dst}
	pathSet := r.lookup(q)
	if pathSet == nil {
		// We didn't find any paths
		return nil
	}
	// We found paths, so we cache them
	r.revTableCache.updatePathSet(pathSet)
	r.pathMap.SetDefault(iaKey, pathSet)
	return pathSet
}

// Register adds pair src-dst to the list of tracked paths.
//
// If this is the first call for the src-dst pair, the function blocks until an
// answer from SCIOND is received. Note that the resolver might asynchronously
// change the paths to a nil slice even before first use if those paths become
// unavailable.
//
// On registration failure an error is returned.
func (r *PR) Register(src, dst *addr.ISD_AS) (*SyncPaths, error) {
	r.Lock()
	defer r.Unlock()

	// If src-dst pair already registered, return a pointer to the slice of paths
	key := iaKey(src, dst)
	dupSP := r.regMap[key]
	if dupSP != nil {
		return dupSP, nil
	}

	if r.regCount == queryChanCap {
		// Reached limit, return error
		return nil, common.NewCError("Unable to register, limit reached",
			"max", queryChanCap)
	}
	r.regCount += 1

	// Reserve memory location for pointer to path
	sp := &SyncPaths{}
	sp.Store(AppPathSet(nil))

	// Save registration memory location in map
	r.regMap[key] = sp

	// Run initial blocking lookup, this populates sp. If the lookup
	// fails, sp will point to an empty slice.
	q := query{src: src, dst: dst, sp: sp}
	pathSet := r.lookup(q)
	sp.Store(pathSet)
	r.revTableReg.updatePathSet(pathSet)

	// Add ia to periodic lookup table
	time.AfterFunc(r.refireInterval, func() {
		r.queries <- q
	})

	return sp, nil
}

// Revoke asynchronously informs SCIOND about a revocation and flushes any
// paths containing the revoked IFID
func (r *PR) Revoke(revInfo common.RawBytes) {
	// Revoke asynchronously to prevent cases where waiting on SCIOND
	// blocks the data plane receiver which got the SCMP packet.
	go r.revoke(revInfo)
}

func (r *PR) revoke(revInfo common.RawBytes) {
	r.Lock()
	defer r.Unlock()

	parsedRev, cerr := path_mgmt.NewRevInfoFromRaw(revInfo)
	if cerr != nil {
		log.Error("Revocation failed, unable to parse revocation info", "err", cerr,
			"revInfo", revInfo)
		return
	}

	reply, err := r.sciond.RevNotification(parsedRev)
	if err != nil {
		log.Error("Revocation failed, unable to inform SCIOND about revocation", "err", err)
		return
	}

	switch reply.Result {
	case sciond.RevUnknown, sciond.RevValid:
		uifid := UIFIDFromValues(parsedRev.IA(), common.IFIDType(parsedRev.IfID))
		r.revTableCache.revoke(uifid)
		revokedPairs := r.revTableReg.revoke(uifid)
		for _, pair := range revokedPairs {
			sp, ok := r.regMap[iaKey(pair.src, pair.dst)]
			if !ok {
				// src-dst pair is no longer tracked
				continue
			}
			q := query{src: pair.src, dst: pair.dst, sp: sp}
			pathSet := r.lookup(q)
			sp.Store(pathSet)
			r.revTableReg.updatePathSet(pathSet)
		}
	case sciond.RevStale:
		log.Warn("Found stale revocation notification", "revInfo", parsedRev)
	case sciond.RevInvalid:
		log.Warn("Found invalid revocation notification", "revInfo", parsedRev)
	}
}

func (r *PR) resolver() {
	for query := range r.queries {
		r.Lock()
		pathSet := r.lookup(query)
		if pathSet != nil {
			// Store path slice atomically
			query.sp.Store(pathSet)
			r.revTableReg.updatePathSet(pathSet)
		}
		r.Unlock()

		// Readd query to queue after duration
		time.AfterFunc(r.refireInterval, func() {
			r.queries <- query
		})
	}
}

// lookup queries SCIOND, blocking while waiting for the response
func (r *PR) lookup(q query) AppPathSet {
	if r.state == sciondDown {
		// Cannot do lookups if SCIOND connection state is down
		return nil
	}

	reply, err := r.sciond.Paths(q.dst, q.src, numReqPaths, sciond.PathReqFlags{})
	if err != nil {
		log.Error("SCIOND network error", "err", err)
		// Network error, cannot connect to SCIOND
		// Spawn asynchronous reconnector if we're the first to notice this
		if r.stateTransition(sciondDown) {
			go r.reconnect()
		}
		return nil
	}

	if reply.ErrorCode != sciond.ErrorOk {
		// SCIOND internal error
		log.Error("Unable to find path", "src", q.src, "dst", q.dst,
			"code", reply.ErrorCode)
		return nil
	}

	return NewAppPathSet(reply)
}

// reconnect repeatedly tries to reconnect to SCIOND
func (r *PR) reconnect() {
	// close existing SCIOND connection, making any goroutine blocked in
	// I/O exit eventually so we can acquire the lock
	r.sciond.Close()

	r.Lock()
	defer r.Unlock()
	for {
		sciondSock, err := sciond.Connect(r.sciondPath)
		if err != nil {
			log.Error("Unable to connect to sciond", "err", err)
			// wait for three seconds before trying again
			time.Sleep(reconnectInterval)
			continue
		}
		r.sciond = sciondSock
		break
	}
	r.stateTransition(sciondUp)
}

// stateTransition changes the internal state to new. If the internal state was
// already equal to new prior to calling this, stateTransition returns false.
func (r *PR) stateTransition(new sciondState) bool {
	if r.state != new {
		r.state = new
		log.Info(fmt.Sprintf("Path resolver changed state to %v", new))
		return true
	}
	return false
}

func iaKey(src, dst *addr.ISD_AS) string {
	return src.String() + "." + dst.String()
}
