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
// Simple path queries are issued via 'Query'; they return an AppPathSet of valid
// paths.
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

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

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
// refire specifies the time between periodic lookups for watched paths. When a
// query for a path older than maxAge reaches the resolver, SCIOND is used to
// refresh the path. New returns with an error if a connection to SCIOND could
// not be established.
func New(srvc sciond.Service, refire, maxAge time.Duration, logger log.Logger) (*PR, error) {
	sciondConn, err := srvc.Connect()
	if err != nil {
		// Let external code handle initial failure
		return nil, common.NewCError("Unable to connect to SCIOND", "err", err)
	}
	pr := &PR{
		sciondService: srvc,
		requestQueue:  make(chan *resolverRequest, queryChanCap),
		Logger:        logger.New("lib", "PathResolver"),
		cache:         newCache(maxAge),
	}
	// Start resolver, which periodically refreshes paths for registered
	// destinations
	r := &resolver{
		sciondService:  pr.sciondService,
		sciondConn:     sciondConn,
		cache:          pr.cache,
		requestQueue:   pr.requestQueue,
		refireInterval: refire,
	}
	go r.run()
	return pr, nil
}

// Query returns a slice of paths between src and dst. If the paths are not
// found in the path resolver's cache, a query to SCIOND is issued and the
// function blocks until the reply is received.
func (r *PR) Query(src, dst *addr.ISD_AS) AppPathSet {
	r.Lock()
	defer r.Unlock()
	if aps, ok := r.cache.getAPS(src, dst); ok {
		return aps
	}
	request := &resolverRequest{
		reqType: reqOneShot,
		src:     src,
		dst:     dst,
		done:    make(chan struct{}),
	}
	r.requestQueue <- request
	<-request.done
	// Cache should be hot now; if we get a miss it means that either the entry
	// expired between the retrieval above and the access (improbable), or no
	// paths are available.
	if aps, ok := r.cache.getAPS(src, dst); ok {
		return aps
	}
	return AppPathSet{}
}

// Watch adds pair src-dst to the list of watched paths.
//
// If this is the first call for the src-dst pair, the function blocks until an
// answer from SCIOND is received. Note that the resolver might asynchronously
// change the paths at any time. Calling Load on the returned object returns
// a reference to a structure containing the currently available paths.
//
// On registration failure an error is returned.
func (r *PR) Watch(src, dst *addr.ISD_AS) (*SyncPaths, error) {
	r.Lock()
	defer r.Unlock()
	if r.cache.isWatched(src, dst) {
		if sp, ok := r.cache.getSP(src, dst); ok {
			return sp, nil
		}
		return nil, common.NewCError("Incoherent cache, src and dst watched but no path set found")
	}
	request := &resolverRequest{
		reqType: reqMonitor,
		src:     src,
		dst:     dst,
		done:    make(chan struct{}),
	}
	r.requestQueue <- request
	<-request.done
	// src-dst is surely registered, and cannot be unregistered at this point
	// because we're holding the lock. If the retrieval below fails, it can
	// only be due to a bug.
	if sp, ok := r.cache.getSP(src, dst); ok {
		return sp, nil
	}
	return nil, common.NewCError("Incoherent cache, src and dst registered but no path set found")
}

func (r *PR) Unwatch(src, dst *addr.ISD_AS) error {
	// FIXME(scrye): Implement this
	return common.NewCError("Function Unwatch not implemented")
}

// WatchFilter returns a pointer to a SyncPaths object that contains paths from
// src to dst that adhere to the specified filter. On path changes the list is
// refreshed automatically.
//
// WatchFilter also adds pair src-dst to the list of tracked paths (if it
// wasn't already tracked).
func (r *PR) WatchFilter(src, dst *addr.ISD_AS, filter *PathPredicate) (*SyncPaths, error) {
	r.Lock()
	defer r.Unlock()
	// If the filter was registered previously, fetch it from the cache
	if sp, ok := r.cache.getFilteredSP(src, dst, filter); ok {
		return sp, nil
	}
	// If the src and dst are not monitored yet, add the request to the resolver's queue
	if !r.cache.isWatched(src, dst) {
		request := &resolverRequest{
			reqType: reqMonitor,
			src:     src,
			dst:     dst,
			done:    make(chan struct{}),
		}
		r.requestQueue <- request
		<-request.done
	}
	r.cache.addFilteredSP(src, dst, filter)
	sp, _ := r.cache.getFilteredSP(src, dst, filter)
	return sp, nil
}

// UnwatchFilter deletes a previously registered filter.
func (r *PR) UnwatchFilter(src, dst *addr.ISD_AS, filter *PathPredicate) error {
	// FIXME(scrye): Implement this
	return common.NewCError("Function UnwatchFilter not implemented")
}

// Revoke asynchronously informs SCIOND about a revocation and flushes any
// paths containing the revoked IFID.
func (r *PR) Revoke(revInfo common.RawBytes) {
	// Revoke asynchronously to prevent cases where waiting on SCIOND
	// blocks the data plane receiver which got the SCMP packet.
	go func() {
		r.Lock()
		defer r.Unlock()
		r.revoke(revInfo)
	}()
}

func (r *PR) revoke(revInfo common.RawBytes) {
	parsedRev, cerr := path_mgmt.NewRevInfoFromRaw(revInfo)
	if cerr != nil {
		log.Error("Revocation failed, unable to parse revocation info", "err", cerr,
			"revInfo", revInfo)
		return
	}
	conn, err := r.sciondService.Connect()
	if err != nil {
		log.Error("Revocation failed, unable to connect to SCIOND", "err", err)
		return
	}
	reply, err := conn.RevNotification(parsedRev)
	if err != nil {
		log.Error("Revocation failed, unable to inform SCIOND about revocation", "err", err)
		return
	}
	err = conn.Close()
	if err != nil {
		log.Error("Revocation error, unable to close SCIOND connection", "err", err)
		// Continue with revocation
	}
	switch reply.Result {
	case sciond.RevUnknown, sciond.RevValid:
		uifid := uifidFromValues(parsedRev.IA(), common.IFIDType(parsedRev.IfID))
		r.cache.revoke(uifid)
	case sciond.RevStale:
		log.Warn("Found stale revocation notification", "revInfo", parsedRev)
	case sciond.RevInvalid:
		log.Warn("Found invalid revocation notification", "revInfo", parsedRev)
	}
}

// resolver receives requests from PR and answers them by contacting SCIOND.
type resolver struct {
	sciondService sciond.Service
	sciondConn    sciond.Connector
	// time between repeated queries to SCIOND
	refireInterval time.Duration
	// information about paths
	cache *cache
	// queue of outstanding requests
	requestQueue chan *resolverRequest
}

// run is the asynchronous path resolver. It grabs requests from a channel, and
// updates the path cache with the result. Periodic requests are readded to the
// channel.
func (r *resolver) run() {
	for request := range r.requestQueue {
		aps := r.lookup(request.src, request.dst)
		switch request.reqType {
		case reqOneShot:
			r.cache.update(request.src, request.dst, aps)
			// Unblock the waiting client
			close(request.done)
		case reqMonitor:
			if !r.cache.isWatched(request.src, request.dst) {
				r.cache.watch(request.src, request.dst)
			}
			r.cache.update(request.src, request.dst, aps)
			// Create new request, without done channel
			newRequest := &resolverRequest{
				src:     request.src,
				dst:     request.dst,
				reqType: reqMonitor,
			}
			time.AfterFunc(r.refireInterval, func() {
				r.requestQueue <- newRequest
			})
			// If someone's waiting for this request to be done, unblock them
			if request.done != nil {
				close(request.done)
			}
		default:
			log.Warn("Unknown query type", "type", request.reqType)
		}
	}
}

// lookup queries SCIOND, blocking while waiting for the response.
func (r *resolver) lookup(src, dst *addr.ISD_AS) AppPathSet {
	reply, err := r.sciondConn.Paths(dst, src, numReqPaths, sciond.PathReqFlags{})
	if err != nil {
		log.Error("SCIOND network error", "err", err)
		r.reconnect()
	}
	if reply.ErrorCode != sciond.ErrorOk {
		// SCIOND internal error, return 0 paths set
		log.Error("Unable to find path", "src", src, "dst", dst, "code", reply.ErrorCode)
		return make(AppPathSet)
	}
	return NewAppPathSet(reply)
}

// reconnect repeatedly tries to reconnect to SCIOND.
func (r *resolver) reconnect() {
	for {
		sciondConn, err := r.sciondService.Connect()
		if err != nil {
			log.Error("Unable to connect to sciond", "err", err)
			// wait for three seconds before trying again
			time.Sleep(reconnectInterval)
			continue
		}
		r.sciondConn = sciondConn
		break
	}
}

type reqType uint

const (
	// Single shot query type, caching the result
	reqOneShot reqType = iota
	// Start periodic queries query type
	reqMonitor
)

// resolverRequest describes the items contained in the resolver's request queue.
type resolverRequest struct {
	src     *addr.ISD_AS
	dst     *addr.ISD_AS
	reqType reqType
	done    chan struct{}
}
