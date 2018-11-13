// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathpol"
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
}

const (
	// DefaultNormalRefire is the wait time after a successful path lookup (for periodic lookups)
	DefaultNormalRefire = time.Minute
	// DefaultErorrRefire is the wait time after a failed path lookup (for periodic lookups)
	DefaultErrorRefire = time.Second
	// DefaultQueryTimeout is the time allocated for a query to SCIOND
	DefaultQueryTimeout = 5 * time.Second
)

const (
	InitialCheckTimeout = time.Second
)

type PR interface {
	// Query returns a set of paths between src and dst.
	Query(ctx context.Context, src, dst addr.IA) spathmeta.AppPathSet
	QueryFilter(ctx context.Context, src, dst addr.IA, policy *pathpol.Policy) spathmeta.AppPathSet
	// Watch returns an object that periodically polls for paths between src
	// and dst.
	//
	// The function blocks until the first answer from SCIOND is received. Note
	// that the resolver might asynchronously change the paths at any time.
	// Calling Load on the returned object returns a reference to a structure
	// containing the currently available paths.
	//
	// Call Destroy on the SyncPaths object to clean up any resources.
	Watch(ctx context.Context, src, dst addr.IA) (*SyncPaths, error)
	// WatchFilter returns a pointer to a SyncPaths object that contains paths from
	// src to dst that adhere to the specified filter. On path changes the list is
	// refreshed automatically.
	WatchFilter(ctx context.Context, src, dst addr.IA,
		filter *pktcls.ActionFilterPaths) (*SyncPaths, error)
	// WatchCount returns the number of active watchers.
	WatchCount() int
	// RevokeRaw informs SCIOND of a revocation.
	RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes)
	// Revoke informs SCIOND of a revocation.
	Revoke(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo)
	// Sciond returns a reference to the SCIOND connection.
	Sciond() sciond.Connector
}

type pr struct {
	sciondService    sciond.Service
	sciondConn       sciond.Connector
	timers           Timers
	runningSyncPaths *runningSyncPathsList
	logger           log.Logger
}

// New connects to SCIOND and spawns the asynchronous path resolver. Parameter
// timers can be used to customize path manager behavior; if any timer is left
// uninitialized, it is assigned the corresponding default value (see package
// constants). When a query for a path older than maxAge reaches the resolver,
// SCIOND is used to refresh the path. New returns with an error if a
// connection to SCIOND could not be established.
func New(conn sciond.Connector, timers *Timers, logger log.Logger) PR {
	return &pr{
		sciondConn:       conn,
		runningSyncPaths: newRunningSyncPathsList(),
		timers:           getTimers(timers),
		logger:           getLogger(logger),
	}
}

func getTimers(timers *Timers) Timers {
	if timers == nil {
		timers = &Timers{}
	}
	if timers.NormalRefire == 0 {
		timers.NormalRefire = DefaultNormalRefire
	}
	if timers.ErrorRefire == 0 {
		timers.ErrorRefire = DefaultErrorRefire
	}
	return *timers
}

func getLogger(logger log.Logger) log.Logger {
	if logger != nil {
		logger = logger.New("lib", "PathResolver")
	}
	return logger
}

func (r *pr) Query(ctx context.Context, src, dst addr.IA) spathmeta.AppPathSet {
	reply, err := r.sciondConn.Paths(ctx, dst, src, numReqPaths, sciond.PathReqFlags{})
	if err != nil {
		log.Error("SCIOND network error", "err", err)
		return make(spathmeta.AppPathSet)
	}
	if reply.ErrorCode != sciond.ErrorOk {
		log.Error("Unable to find path", "src", src, "dst", dst, "code", reply.ErrorCode)
		return make(spathmeta.AppPathSet)
	}
	return spathmeta.NewAppPathSet(reply)
}

func (r *pr) QueryFilter(ctx context.Context, src, dst addr.IA,
	policy *pathpol.Policy) spathmeta.AppPathSet {

	aps := r.Query(ctx, src, dst)
	// Delete paths that do not match the path policy
	return policy.Act(aps).(spathmeta.AppPathSet)
}

func (r *pr) Watch(ctx context.Context, src, dst addr.IA) (*SyncPaths, error) {
	aps := r.Query(ctx, src, dst)
	sp := NewSyncPaths()
	sp.update(aps)

	closeC := make(chan struct{})
	element := r.runningSyncPaths.Insert(sp)
	var once sync.Once
	sp.setDestructor(func() {
		once.Do(func() {
			close(closeC)
			r.runningSyncPaths.Remove(element)
		})
	})

	waitDuration := r.getWaitDuration(len(aps) == 0)
	go func() {
		defer log.LogPanicAndExit()
		for {
			select {
			case <-closeC:
				return
			case <-time.After(waitDuration):
				ctx, cancelF := context.WithTimeout(context.Background(), DefaultQueryTimeout)
				aps := r.Query(ctx, src, dst)
				cancelF()
				sp.update(aps)
				waitDuration = r.getWaitDuration(len(aps) == 0)
			}
		}
	}()
	return sp, nil
}

func (r *pr) getWaitDuration(isError bool) time.Duration {
	if isError {
		return r.timers.ErrorRefire
	}
	return r.timers.NormalRefire
}

func (r *pr) WatchFilter(ctx context.Context, src, dst addr.IA,
	filter *pktcls.ActionFilterPaths) (*SyncPaths, error) {

	aps := r.Query(ctx, src, dst)
	sp := NewSyncPaths()
	aps = filter.Act(aps).(spathmeta.AppPathSet)
	sp.update(aps)
	go func() {
		for {
			aps := r.Query(context.TODO(), src, dst)
			aps = filter.Act(aps).(spathmeta.AppPathSet)
			sp.update(aps)
		}
	}()
	return sp, nil
}

func (r *pr) WatchCount() int {
	return r.runningSyncPaths.Len()
}

func (r *pr) RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes) {
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(rawSRevInfo)
	if err != nil {
		log.Error("Revocation failed, unable to parse signed revocation info",
			"raw", rawSRevInfo, "err", err)
		return
	}
	r.Revoke(ctx, sRevInfo)
}

func (r *pr) Revoke(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo) {
	reply, err := r.sciondConn.RevNotification(context.Background(), sRevInfo)
	if err != nil {
		log.Error("Revocation failed, unable to inform SCIOND about revocation", "err", err)
		return
	}
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		log.Error("Revocation failed, unable to parse revocation info",
			"sRevInfo", sRevInfo, "err", err)
		return
	}
	switch reply.Result {
	case sciond.RevUnknown, sciond.RevValid:
		// Each watcher contains a cache; purge paths matched by the revocation
		// immediately from each cache.
		pi := sciond.PathInterface{RawIsdas: revInfo.IA().IAInt(),
			IfID: common.IFIDType(revInfo.IfID)}
		f := func(e *list.Element) {
			sp := e.Value.(*SyncPaths)
			aps := sp.Load().APS
			aps = revokeInternal(aps, pi)
			sp.update(aps)
		}
		r.runningSyncPaths.Apply(f)
	case sciond.RevStale:
		log.Warn("Found stale revocation notification", "revInfo", revInfo)
	case sciond.RevInvalid:
		log.Warn("Found invalid revocation notification", "revInfo", revInfo)
	}
}

func (r *pr) Sciond() sciond.Connector {
	return r.sciondConn
}

func revokeInternal(aps spathmeta.AppPathSet, pi sciond.PathInterface) spathmeta.AppPathSet {
	other := make(spathmeta.AppPathSet)
	for key, path := range aps {
		if !matches(path, pi) {
			other[key] = path
		}
	}
	return other
}

func matches(path *spathmeta.AppPath, predicatePI sciond.PathInterface) bool {
	for _, pi := range path.Entry.Path.Interfaces {
		if pi.Eq(&predicatePI) {
			return true
		}
	}
	return false
}

type runningSyncPathsList struct {
	mtx  sync.Mutex
	list *list.List
}

func newRunningSyncPathsList() *runningSyncPathsList {
	return &runningSyncPathsList{list: list.New()}
}

func (spl *runningSyncPathsList) Insert(v interface{}) *list.Element {
	spl.mtx.Lock()
	defer spl.mtx.Unlock()
	return spl.list.PushBack(v)
}

func (spl *runningSyncPathsList) Remove(e *list.Element) interface{} {
	spl.mtx.Lock()
	defer spl.mtx.Unlock()
	return spl.list.Remove(e)
}

func (spl *runningSyncPathsList) Apply(f func(e *list.Element)) {
	spl.mtx.Lock()
	defer spl.mtx.Unlock()
	for current := spl.list.Front(); current != nil; current = current.Next() {
		f(current)
	}
}

func (spl *runningSyncPathsList) Len() int {
	spl.mtx.Lock()
	defer spl.mtx.Unlock()
	return spl.list.Len()
}
