package scion

import (
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
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
	requestQueue       chan *PathQuery
	context            *Context
	defaultPathTimeout time.Duration
	pathCache          map[uint64]PathSet
	pathLock           sync.Mutex
	sciond             *sciond.Connector
}

func NewPathManager(context *Context, sciondPath string) (*PathManager, error) {
	var err error
	pm := &PathManager{}
	pm.requestQueue = make(chan *PathQuery, 256)
	pm.context = context
	pm.defaultPathTimeout = 30 * time.Second
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
		// FIXME(scrye): sciond might timeout indefinitely here, need to add a deadline
		reply, err := pm.sciond.Paths(query.dst, query.src, 1, sciond.PathReqFlags{})
		if err != nil {
			log.Warn("Path retrieval error", "src", query.src, "dst", query.dst, "err", err)
			// rearm path query, this time with no response channel (since nobody's listening)
			time.AfterFunc(5*time.Second, func() { pm.requestQueue <- query.DisconnectedCopy() })
			if query.reply != nil {
				query.reply <- PathResponse{sciond.PathReplyEntry{}, err}
			}
			continue
		}

		if reply.ErrorCode != sciond.ErrorOk {
			log.Info("Path query resolved with error", "src", query.src, "dst", query.dst,
				"error", reply.ErrorCode)
			// rearm path query, this time with no response channel (since nobody's listening)
			time.AfterFunc(5*time.Second, func() { pm.requestQueue <- query.DisconnectedCopy() })
			if query.reply != nil {
				query.reply <- PathResponse{sciond.PathReplyEntry{},
					common.NewError("Error from SCIOND", "code", reply.ErrorCode)}
			}
			continue
		}

		pm.UpdatePaths(query.src, query.dst, PathSetFromSlice(reply.Entries))
		if query.reply != nil {
			query.reply <- PathResponse{reply.Entries[0], nil}
		}

		// Rearm path query for reachable destination AS
		time.AfterFunc(60*time.Second, func() { pm.requestQueue <- query.DisconnectedCopy() })
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
	pm.pathLock.Lock()
	if pathSet, found := pm.pathCache[key]; found && len(pathSet) > 0 {
		pm.pathLock.Unlock()
		return pathSet.first(), nil
	}
	pm.pathLock.Unlock()

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
	if pm.pathCache[key] == nil {
		pm.pathCache[key] = paths
	} else {
		pm.pathCache[key].removeExcept(paths)
		pm.pathCache[key].insert(paths)
	}
	return nil
}

// PathSet contains MTU and BR information for known paths
type PathSet map[string]sciond.PathReplyEntry

func PathSetFromSlice(paths []sciond.PathReplyEntry) PathSet {
	s := make(PathSet)
	for _, v := range paths {
		s[string(v.Path.FwdPath)] = v
	}
	return s
}

func (s PathSet) removeExcept(op PathSet) {
	for k := range s {
		if _, found := op[k]; !found {
			delete(s, k)
		}
	}
}

func (s PathSet) insert(op PathSet) {
	for k, v := range op {
		s[k] = v
	}
}

func (s PathSet) remove(op PathSet) {
	for k := range op {
		delete(s, k)
	}
}

func (s PathSet) first() sciond.PathReplyEntry {
	for _, v := range s {
		return v
	}
	panic("Unable to select first of empty pathSet")
}
