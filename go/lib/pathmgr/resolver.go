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
	"time"

	log "github.com/inconshreveable/log15"

	liblog "github.com/scionproto/scion/go/lib/log"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
)

// resolver receives requests from PR and answers them by contacting SCIOND.
type resolver struct {
	sciondService sciond.Service
	sciondConn    sciond.Connector
	// Wait time after a failed (error or empty) path lookup (for periodic lookups)
	errorRefire time.Duration
	// Wait time after a successful path lookup (for periodic lookups)
	normalRefire time.Duration
	// information about paths
	cache *cache
	// queue of outstanding requests
	requestQueue chan *resolverRequest
}

// run is the asynchronous path resolver. It grabs requests from a channel, and
// updates the path cache with the result. Periodic requests are readded to the
// channel.
func (r *resolver) run() {
	defer liblog.LogPanicAndExit()
	for request := range r.requestQueue {
		aps := r.lookup(request.src, request.dst)
		switch request.reqType {
		case reqOneShot:
			r.cache.update(request.src, request.dst, aps)
			// Unblock the waiting client
			close(request.done)
		case reqMonitor:
			r.cache.update(request.src, request.dst, aps)
			// If someone's waiting for this request to be done, unblock them
			if request.done != nil {
				close(request.done)
			}
			// FIXME(scrye): this needs to be tested after removal methods are implemented
			if r.cache.isWatched(request.src, request.dst) {
				// Create new request, without done channel
				request.done = nil
				var wait time.Duration
				if len(aps) == 0 {
					wait = r.errorRefire
				} else {
					wait = r.normalRefire
				}
				time.AfterFunc(wait, func() {
					r.requestQueue <- request
				})
			}
		default:
			log.Warn("Unknown query type", "request", request)
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
