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
package pathmgr

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

type PR struct {
	sync.Mutex     // lookup, reconnect and Register acquire this lock as separate goroutines
	sciondPath     string
	sciond         *sciond.Connector
	regMap         map[string]*SyncPaths // map containing tracked srcIA-dstIA pairs
	regCount       uint64                // number of IAs registered for priority tracking
	queries        chan query            // used for keeping track of which queries need to be sent
	state          sciondState           // state of SCIOND connection
	refireInterval time.Duration         // Duration between two path lookups for a registered path
	log.Logger
}

// New connects to SCIOND and spawns the asynchronous path resolver. The
// resolver refreshes each path periodically, waiting refireInterval between
// queries. New returns with an error if a connection to SCIOND could not be
// established.
func New(sciondPath string, refireInterval time.Duration, logger log.Logger) (*PR, error) {
	// Connect to sciond
	sciondSock, err := sciond.Connect(sciondPath)
	if err != nil {
		// Let external code handle initial failure
		return nil, common.NewError("Unable to connect to SCIOND", "err", err)
	}

	pr := &PR{sciondPath: sciondPath,
		sciond:         sciondSock,
		regMap:         make(map[string]*SyncPaths),
		queries:        make(chan query, queryChanCap),
		state:          sciondUp,
		refireInterval: refireInterval,
		Logger:         logger.New("pathmgr")}

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
	r.Lock()
	defer r.Unlock()

	// If src-dst pair already registered, return a pointer to the slice of paths
	key := src.String() + "." + dst.String()
	dupSP := r.regMap[key]
	if dupSP != nil {
		return dupSP, nil
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

	// Save registration memory location in map
	r.regMap[key] = sp

	// Run initial blocking lookup, this populates sp. If the lookup
	// fails, sp will point to an empty slice.
	q := query{src: src, dst: dst, sp: sp}
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
		r.Lock()
		r.lookup(query)
		r.Unlock()

		// Readd query to queue after duration
		time.AfterFunc(r.refireInterval, func() {
			r.queries <- query
		})
	}
}

// lookup queries SCIOND, blocking while waiting for the response
func (r *PR) lookup(q query) {
	if r.state == sciondDown {
		// Cannot do lookups if SCIOND connection state is down
		return
	}

	reply, err := r.sciond.Paths(q.dst, q.src, numReqPaths, sciond.PathReqFlags{})
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
	// close existing SCIOND connection, making any goroutines blocked in
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
	r.stateTransition(sciondDown, sciondUp)
}

// stateTransition transitions from current internal state old to internal
// state new; if current state does not match old, it returns false and no
// changes are made
func (r *PR) stateTransition(old, new sciondState) bool {
	if r.state == old {
		r.state = new
		log.Info(fmt.Sprintf("Path resolver changed state to %v", new))
		return true
	}
	return false
}
