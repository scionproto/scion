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

// package pr implement an asynchronous Path Resolver for SCION Paths.
//
// A new resolver can be instantiated by calling `New`. Path queries can be
// added with `Register`, which returns a thread-safe pointer to a slice of
// paths; if no valid paths exist the slice is empty. Access to the underlying
// slice is obtained by calling `Load` on the pointer.  When refreshing paths,
// the resolver will atomically change the value of the pointer to point to a
// new slice of paths. Fresh paths can be obtained by calling Load again.
//
// An example of how this package can be used can be found in the associated
// test file.
//
// If the connection to SCIOND fails, the resolver automatically attempts to
// reestablish the connection. During this period, paths are not expired. Paths
// will be transparently refreshed after reconnecting to SCIOND.
package pr

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	// For now, log errors in library because there's no asynchronous
	// mechanism to gather them
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

const (
	// maximum number of IAs that can be registered for priority tracking
	queryChanCap uint64 = 1 << 10
	// the number of max paths requested in each SCIOND query
	numReqPaths = 5
	// time between reconnection attempts if SCIOND fails
	reconnectInterval = 3 * time.Second
)

// query contains the context needed to issue and update a query
type query struct {
	src, dst *addr.ISD_AS
	sp       *SyncPaths
}

// SyncPaths contains a concurrency-safe reference to a slice `[]*FwdPathMeta`.
// Callers can safely `Load` the reference and use the paths within. At any
// moment, the path resolver can change the value of the reference within a
// SyncPaths to a different slice containing new paths. Calling code should
// reload the reference often to make sure the paths are fresh.
type SyncPaths struct {
	atomic.Value
}

// Overwrite Load to avoid external type assertions
func (sp *SyncPaths) Load() []*sciond.FwdPathMeta {
	return sp.Value.Load().([]*sciond.FwdPathMeta)
}

// sciondState is used to track the health of the connection to SCIOND
type sciondState uint64

const (
	// SCIOND is considered down due to a query failing at network level
	sciondDown sciondState = iota
	// SCIOND is considered up
	sciondUp
)

func (state sciondState) String() string {
	switch state {
	case sciondDown:
		return "down"
	case sciondUp:
		return "up"
	default:
		return "unknown"
	}
}

type PR struct {
	sciondPath string
	// sciond is _not_ currently concurrency safe and must be protected by locks
	sciondLock sync.Mutex
	sciond     *sciond.Connector

	regMapMutex sync.Mutex      // enforces concurrency safety for `regMap`
	regMap      map[string]bool // thread safe map containing tracked srcIA-dstIA pairs

	regCount       uint64        // number of IAs registered for priority tracking
	queries        chan query    // used for keeping track of which queries need to be sent
	state          sciondState   // state of SCIOND connection
	refireInterval time.Duration // Duration between two path lookups for a registered path
}

// New connects to SCIOND and spawns the asynchronous path resolver. The
// resolver refreshes each path periodically, waiting refireInterval between
// queries. New returns with an error if a connection to SCIOND could not be
// established.
func New(sciondPath string, refireInterval time.Duration) (*PR, error) {
	// Connect to sciond
	sciondSock, err := sciond.Connect(sciondPath)
	if err != nil {
		// Let external code handle initial failure
		return nil, common.NewError("Unable to connect to SCIOND", "err", err)
	}

	pr := &PR{sciondPath: sciondPath,
		sciond:         sciondSock,
		regMap:         make(map[string]bool),
		queries:        make(chan query, queryChanCap),
		state:          sciondUp,
		refireInterval: refireInterval}

	// Start resolver, which periodically spawns SCIOND query goroutines
	// for tracked ia's
	go pr.resolver()
	return pr, nil
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
	// Sanity check for double registrations
	r.regMapMutex.Lock()
	_, duplicate := r.regMap[src.String()+"."+dst.String()]
	r.regMapMutex.Unlock()
	if duplicate {
		return nil, common.NewError("Unable to register duplicate entry",
			"src", src, "dst", dst)
	}

	if atomic.CompareAndSwapUint64(&r.regCount, queryChanCap, queryChanCap) {
		// Reached limit, return error
		return nil, common.NewError("Unable to register, limit reached",
			"max", queryChanCap)
	}
	atomic.AddUint64(&r.regCount, 1)

	// Reserve memory location for pointer to path
	sp := &SyncPaths{}
	sp.Store([]*sciond.FwdPathMeta{})

	q := query{src: src, dst: dst, sp: sp}

	// Run initial blocking lookup, this populates sp. If the lookup
	// fails, sp will point to an empty slice.
	r.lookup(q)

	// Add ia to periodic lookup table
	time.AfterFunc(r.refireInterval, func() {
		r.queries <- q
	})

	return sp, nil
}

func (r *PR) resolver() {
	for query := range r.queries {
		// Spawn blocking sub-goroutine
		go r.lookup(query)

		// Readd query to queue after duration
		time.AfterFunc(r.refireInterval, func() {
			r.queries <- query
		})
	}
}

// lookup queries SCIOND, blocking while waiting for the response
func (r *PR) lookup(q query) {
	if r.stateCheck(sciondDown) {
		// Cannot do lookups if SCIOND connection state is down
		return
	}

	r.sciondLock.Lock()
	reply, err := r.sciond.Paths(q.dst, q.src, numReqPaths, sciond.PathReqFlags{})
	r.sciondLock.Unlock()
	if err != nil {
		log.Error("SCIOND network error", "err", err)
		// Network error, cannot connect to SCIOND
		// Spawn asynchronous reconnector if we're the first to notice this
		if r.stateTransition(sciondUp, sciondDown) {
			go r.reconnect()
		}
		return
	}

	if reply.ErrorCode != sciond.ErrorOk {
		// SCIOND internal error
		log.Error("Unable to find path", "src", q.src, "dst", q.dst,
			"code", reply.ErrorCode)

		// NB: keep the old path if lookup failed
		return
	}

	// Prepare new path slice
	paths := make([]*sciond.FwdPathMeta, len(reply.Entries))
	for i := range reply.Entries {
		paths[i] = &reply.Entries[i].Path
	}

	// Store path slice atomically
	q.sp.Store(paths)
}

// reconnect repeatedly tries to reconnect to SCIOND
func (r *PR) reconnect() {
	// close existing connection, making any goroutines blocked in I/O
	// exit eventually
	r.sciond.Close()

	for {
		sciondSock, err := sciond.Connect(r.sciondPath)
		if err != nil {
			log.Error("Unable to connect to sciond", "err", err)
			// wait for three seconds before trying again
			time.Sleep(reconnectInterval)
			continue
		}

		// make sure no other goroutine is still using r.sciond
		r.sciondLock.Lock()
		r.sciond = sciondSock
		r.sciondLock.Unlock()
		break
	}
	r.stateTransition(sciondDown, sciondUp)
}

// stateCheck returns true if state matches internal resolver state
func (r *PR) stateCheck(state sciondState) bool {
	return atomic.CompareAndSwapUint64((*uint64)(&r.state), uint64(state),
		uint64(state))
}

// stateTransition atomically transitions from current internal state old to
// internal state new; if current state does not match old, it returns false
// and no changes are made
func (r *PR) stateTransition(old, new sciondState) bool {
	swap := atomic.CompareAndSwapUint64((*uint64)(&r.state), uint64(old), uint64(new))
	if swap {
		log.Info(fmt.Sprintf("Path resolver changed state to %v", new))
	}
	return swap
}
