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

// Package pathmgr implements an asynchronous Path Resolver for SCION Paths.
//
// A new resolver can be instantiated by calling `New`. There are two types of
// supported path queries, simple or periodic.
//
// Simple path queries are issued via 'Query'; they return an
// spathmeta.AppPathSet of valid paths.
//
// Periodic path queries are added via 'Watch', which returns a pointer to a
// thread-safe SyncPaths object; calling Load on the object returns the data
// associated with the watch, which includes the set of paths. When updating
// paths, the resolver will atomically change the value within the SyncPaths
// object. The data can be accessed by calling Load again.
//
// An example of how this package can be used can be found in the associated
// infra test file.
//
// If the connection to SCIOND fails, the resolver automatically attempts to
// reestablish the connection. During this period, paths are not expired. Paths
// will be transparently refreshed after reconnecting to SCIOND.
package pathmgr

// The manager is composed of the public PR struct, which is a proxy that
// forward queries to the asynchronous resolver. Both the proxy and the
// resolver operate over a thread-safe cache which contains path information.

import (
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

// Timers is used to customize the timers for a new Path Manager.
type Timers struct {
	// Wait time after a successful path lookup (for periodic lookups)
	NormalRefire time.Duration
	// Wait time after a failed (error or empty) path lookup (for periodic lookups)
	ErrorRefire time.Duration
	// Duration after which a path is considered stale
	MaxAge time.Duration
}

const (
	// Default wait time after a successful path lookup (for periodic lookups)
	DefaultNormalRefire = time.Minute
	// Default wait time after a failed path lookup (for periodic lookups)
	DefaultErrorRefire = time.Second
	// Default time after which a path is considered stale
	DefaultMaxAge = 6 * time.Hour
)

func setDefaultTimers(timers *Timers) {
	if timers.NormalRefire == 0 {
		timers.NormalRefire = DefaultNormalRefire
	}
	if timers.ErrorRefire == 0 {
		timers.ErrorRefire = DefaultErrorRefire
	}
	if timers.MaxAge == 0 {
		timers.MaxAge = DefaultMaxAge
	}
}

type PR struct {
	// Lookup, reconnect and Register acquire this lock as separate goroutines
	sync.Mutex
	sciondService sciond.Service
	// Number of IAs registered for priority tracking
	regCount uint64
	// Used for keeping track of which queries need to be sent
	requestQueue chan *resolverRequest
	cache        *cache
	log.Logger
}

// New connects to SCIOND and spawns the asynchronous path resolver. Parameter
// timers can be used to customize path manager behavior; if any timer is left
// uninitialized, it is assigned the corresponding default value (see package
// constants). When a query for a path older than maxAge reaches the resolver,
// SCIOND is used to refresh the path. New returns with an error if a
// connection to SCIOND could not be established.
func New(srvc sciond.Service, timers *Timers, logger log.Logger) (*PR, error) {
	sciondConn, err := srvc.Connect()
	if err != nil {
		// Let external code handle initial failure
		return nil, common.NewBasicError("Unable to connect to SCIOND", err)
	}
	if timers == nil {
		timers = &Timers{}
	}
	setDefaultTimers(timers)
	pr := &PR{
		sciondService: srvc,
		requestQueue:  make(chan *resolverRequest, queryChanCap),
		Logger:        logger.New("lib", "PathResolver"),
		cache:         newCache(timers.MaxAge),
	}
	// Start resolver, which periodically refreshes paths for registered
	// destinations
	r := &resolver{
		sciondService: pr.sciondService,
		sciondConn:    sciondConn,
		cache:         pr.cache,
		requestQueue:  pr.requestQueue,
		normalRefire:  timers.NormalRefire,
		errorRefire:   timers.ErrorRefire,
	}
	go r.run()
	return pr, nil
}

// Query returns a slice of paths between src and dst. If the paths are not
// found in the path resolver's cache, a query to SCIOND is issued and the
// function blocks until the reply is received.
func (r *PR) Query(src, dst addr.IA) spathmeta.AppPathSet {
	r.Lock()
	defer r.Unlock()
	if aps, ok := r.cache.getAPS(src, dst); ok {
		return aps
	}
	done := make(chan struct{})
	request := &resolverRequest{
		reqType: reqOneShot,
		src:     src,
		dst:     dst,
		done:    done,
	}
	r.requestQueue <- request
	<-done
	// Cache should be hot now; if we get a miss it means that either the entry
	// expired between the retrieval above and the access (improbable), or no
	// paths are available.
	if aps, ok := r.cache.getAPS(src, dst); ok {
		return aps.Copy()
	}
	return spathmeta.AppPathSet{}
}

func (r *PR) QueryFilter(src, dst addr.IA, filter *pktcls.ActionFilterPaths) spathmeta.AppPathSet {
	aps := r.Query(src, dst)
	// Delete paths that do not match the predicate

	return filter.Act(aps).(spathmeta.AppPathSet)
}

// Watch adds pair src-dst to the list of watched paths.
//
// If this is the first call for the src-dst pair, the function blocks until an
// answer from SCIOND is received. Note that the resolver might asynchronously
// change the paths at any time. Calling Load on the returned object returns
// a reference to a structure containing the currently available paths.
//
// On registration failure an error is returned.
func (r *PR) Watch(src, dst addr.IA) (*SyncPaths, error) {
	return r.WatchFilter(src, dst, nil)
}

func (r *PR) Unwatch(src, dst addr.IA) error {
	return r.UnwatchFilter(src, dst, nil)
}

// WatchFilter returns a pointer to a SyncPaths object that contains paths from
// src to dst that adhere to the specified filter. On path changes the list is
// refreshed automatically.
//
// WatchFilter also adds pair src-dst to the list of tracked paths (if it
// wasn't already tracked).
func (r *PR) WatchFilter(src, dst addr.IA, filter *pktcls.ActionFilterPaths) (*SyncPaths, error) {
	r.Lock()
	defer r.Unlock()
	// If the src and dst are not monitored yet, add the request to the resolver's queue
	if !r.cache.isWatched(src, dst) {
		done := make(chan struct{})
		request := &resolverRequest{
			reqType: reqMonitor,
			src:     src,
			dst:     dst,
			done:    done,
		}
		r.cache.watch(src, dst, filter)
		r.requestQueue <- request
		<-done
	} else {
		// Only increment reference count
		r.cache.watch(src, dst, filter)
	}
	sp, _ := r.cache.getWatch(src, dst, filter)
	return sp, nil
}

// UnwatchFilter deletes a previously registered filter.
func (r *PR) UnwatchFilter(src, dst addr.IA, filter *pktcls.ActionFilterPaths) error {
	r.Lock()
	defer r.Unlock()
	return r.cache.removeWatch(src, dst, filter)
}

// Revoke asynchronously informs SCIOND about a revocation and flushes any
// paths containing the revoked IFID.
func (r *PR) Revoke(revInfo common.RawBytes) {
	// Revoke asynchronously to prevent cases where waiting on SCIOND
	// blocks the data plane receiver which got the SCMP packet.
	go func() {
		defer liblog.LogPanicAndExit()
		r.Lock()
		defer r.Unlock()
		r.revoke(revInfo)
	}()
}

func (r *PR) revoke(b common.RawBytes) {
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(b)
	if err != nil {
		log.Error("Revocation failed, unable to parse signed revocation info",
			"raw", b, "err", err)
		return
	}
	conn, err := r.sciondService.Connect()
	if err != nil {
		log.Error("Revocation failed, unable to connect to SCIOND", "err", err)
		return
	}
	reply, err := conn.RevNotification(sRevInfo)
	if err != nil {
		log.Error("Revocation failed, unable to inform SCIOND about revocation", "err", err)
		return
	}
	err = conn.Close()
	if err != nil {
		log.Error("Revocation error, unable to close SCIOND connection", "err", err)
		// Continue with revocation
	}
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		log.Error("Revocation failed, unable to parse revocation info",
			"sRevInfo", sRevInfo, "err", err)
		return
	}
	switch reply.Result {
	case sciond.RevUnknown, sciond.RevValid:
		uifid := uifidFromValues(revInfo.IA(), common.IFIDType(revInfo.IfID))
		r.cache.revoke(uifid)
	case sciond.RevStale:
		log.Warn("Found stale revocation notification", "revInfo", revInfo)
	case sciond.RevInvalid:
		log.Warn("Found invalid revocation notification", "revInfo", revInfo)
	}
}
