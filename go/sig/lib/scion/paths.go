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

package scion

import (
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

const (
	RequestQueueCapacity = 256
	DefaultPathTimeout   = 30 * time.Second
	ShortPathTimeout     = 5 * time.Second
)

type PathQuery struct {
	src   *addr.ISD_AS
	dst   *addr.ISD_AS
	reply chan PathResponse
}

func NewPathQuery(src, dst *addr.ISD_AS) *PathQuery {
	query := &PathQuery{src: src, dst: dst}
	query.reply = make(chan PathResponse, 1)
	return query
}

// DisconnectedCopy creates a copy of a PathQuery, without a blocking response channel
func (query *PathQuery) DisconnectedCopy() *PathQuery {
	new := &PathQuery{src: query.src, dst: query.dst}
	return new
}

type PathResponse struct {
	path sciond.PathReplyEntry
	err  error
}

func getKey(srcIA *addr.ISD_AS, dstIA *addr.ISD_AS) uint64 {
	return uint64(srcIA.Uint32())<<32 + uint64(dstIA.Uint32())
}

// PathManager asynchronously keeps paths up to date for known remote ASes
type PathManager struct {
	pathLock     sync.RWMutex
	requestQueue chan *PathQuery
	pathCache    map[uint64]PathSet
	sciond       *sciond.Connector
}

func NewPathManager(sciondPath string) (*PathManager, error) {
	var err error
	pm := &PathManager{}
	pm.requestQueue = make(chan *PathQuery, RequestQueueCapacity)
	pm.pathCache = make(map[uint64]PathSet)

	pm.sciond, err = sciond.Connect(sciondPath)
	if err != nil {
		return nil, err
	}
	go pm.run()
	return pm, nil
}

func (pm *PathManager) run() {
	for {
		query := <-pm.requestQueue
		// FIXME(scrye): sciond might timeout indefinitely here, need
		// to add a deadline
		reply, err := pm.sciond.Paths(query.dst, query.src, 1, sciond.PathReqFlags{})
		if err != nil {
			log.Warn("Path retrieval error", "src", query.src,
				"dst", query.dst, "err", err)
			// rearm path query, this time with no response channel
			// (since nobody's listening)
			time.AfterFunc(ShortPathTimeout,
				func() { pm.requestQueue <- query.DisconnectedCopy() })
			if query.reply != nil {
				query.reply <- PathResponse{sciond.PathReplyEntry{}, err}
			}
			continue
		}

		if reply.ErrorCode != sciond.ErrorOk {
			log.Info("Path query resolved with error", "src", query.src,
				"dst", query.dst, "error", reply.ErrorCode)
			// rearm path query, this time with no response channel
			// (since nobody's listening)
			time.AfterFunc(ShortPathTimeout,
				func() { pm.requestQueue <- query.DisconnectedCopy() })
			if query.reply != nil {
				query.reply <- PathResponse{sciond.PathReplyEntry{},
					common.NewCError("Error from SCIOND",
						"code", reply.ErrorCode)}
			}
			continue
		}

		pm.UpdatePaths(query.src, query.dst, reply.Entries)
		if query.reply != nil {
			query.reply <- PathResponse{reply.Entries[0], nil}
		}

		// Rearm path query for reachable destination AS
		time.AfterFunc(DefaultPathTimeout, func() { pm.requestQueue <- query.DisconnectedCopy() })
	}
}

// FindPath returns a path for dst and registers dst with PathManager. If no
// path is cached, the function waits for a limited time for a response from
// SCIOND. On timeout, no path is returned but the destination remains
// registered. The path manager will periodically reattempt to get the paths
// for destinations which timed out, while also refreshing paths to known
// destinations.
func (pm *PathManager) FindPath(src, dst *addr.ISD_AS) (sciond.PathReplyEntry, error) {
	key := getKey(src, dst)
	pm.pathLock.RLock()
	if pathSet, found := pm.pathCache[key]; found && len(pathSet) > 0 {
		pm.pathLock.RUnlock()
		path, err := pathSet.first()
		return *path, err
	}
	pm.pathLock.RUnlock()

	query := NewPathQuery(src, dst)
	pm.requestQueue <- query
	response := <-query.reply
	return response.path, response.err
}

func (pm *PathManager) UpdatePaths(src, dst *addr.ISD_AS, paths PathSet) error {
	pm.pathLock.Lock()
	defer pm.pathLock.Unlock()

	if len(paths) == 0 {
		return nil
	}

	key := getKey(src, dst)
	pm.pathCache[key] = paths
	return nil
}

// PathSet contains MTU and BR information for known paths
type PathSet []sciond.PathReplyEntry

func (s PathSet) first() (*sciond.PathReplyEntry, error) {
	if len(s) == 0 {
		return nil, common.NewCError("Unable to select first of empty pathSet")
	}
	return &s[0], nil
}
