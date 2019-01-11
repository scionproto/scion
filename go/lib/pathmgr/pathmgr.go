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
package pathmgr

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

func (timers *Timers) initDefaults() {
	if timers.NormalRefire == 0 {
		timers.NormalRefire = DefaultNormalRefire
	}
	if timers.ErrorRefire == 0 {
		timers.ErrorRefire = DefaultErrorRefire
	}
}

const (
	// DefaultNormalRefire is the wait time after a successful path lookup (for periodic lookups)
	DefaultNormalRefire = time.Minute
	// DefaultErorrRefire is the wait time after a failed path lookup (for periodic lookups)
	DefaultErrorRefire = time.Second
	// DefaultQueryTimeout is the time allocated for a query to SCIOND
	DefaultQueryTimeout = 5 * time.Second
)

type Resolver interface {
	// Query returns a set of paths between src and dst.
	Query(ctx context.Context, src, dst addr.IA, flags sciond.PathReqFlags) spathmeta.AppPathSet
	// QueryFilter returns a set of paths between src and dst that satisfy
	// policy. A nil policy will not delete any paths.
	QueryFilter(ctx context.Context, src, dst addr.IA, policy *pathpol.Policy) spathmeta.AppPathSet
	// Watch returns an object that periodically polls for paths between src
	// and dst.
	//
	// The function blocks until the first answer from SCIOND is received. The
	// amount of time is dictated by ctx. Note that the resolver might
	// asynchronously change the paths at any time. Calling Load on the
	// returned object returns a reference to a structure containing the
	// currently available paths.
	//
	// The asynchronous worker is not subject to ctx; thus, it has infinite
	// lifetime or until Destroy is called on the SyncPaths object to clean up
	// any resources.
	Watch(ctx context.Context, src, dst addr.IA) (*SyncPaths, error)
	// WatchFilter returns a pointer to a SyncPaths object that contains paths from
	// src to dst that adhere to the specified filter. On path changes the list is
	// refreshed automatically.
	//
	// A nil filter will not delete any paths.
	WatchFilter(ctx context.Context, src, dst addr.IA, filter *pathpol.Policy) (*SyncPaths, error)
	// WatchCount returns the number of active watchers.
	WatchCount() int
	// RevokeRaw informs SCIOND of a revocation.
	RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes)
	// Revoke informs SCIOND of a revocation.
	Revoke(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo)
	// Sciond returns a reference to the SCIOND connection.
	Sciond() sciond.Connector
}

type resolver struct {
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
func New(conn sciond.Connector, timers Timers, logger log.Logger) Resolver {
	timers.initDefaults()
	return &resolver{
		sciondConn:       conn,
		runningSyncPaths: newRunningSyncPathsList(),
		timers:           timers,
		logger:           getLogger(logger),
	}
}

func (r *resolver) Query(ctx context.Context, src, dst addr.IA,
	flags sciond.PathReqFlags) spathmeta.AppPathSet {

	reply, err := r.sciondConn.Paths(ctx, dst, src, numReqPaths, flags)
	if err != nil {
		r.logger.Error("SCIOND network error", "err", err)
		return make(spathmeta.AppPathSet)
	}
	if reply.ErrorCode != sciond.ErrorOk {
		r.logger.Error("Unable to find path", "src", src, "dst", dst, "code", reply.ErrorCode)
		return make(spathmeta.AppPathSet)
	}
	return spathmeta.NewAppPathSet(reply)
}

func (r *resolver) QueryFilter(ctx context.Context, src, dst addr.IA,
	policy *pathpol.Policy) spathmeta.AppPathSet {

	aps := r.Query(ctx, src, dst, sciond.PathReqFlags{})
	if policy == nil {
		return aps
	}
	return policy.Act(aps).(spathmeta.AppPathSet)
}

func (r *resolver) WatchFilter(ctx context.Context, src, dst addr.IA,
	filter *pathpol.Policy) (*SyncPaths, error) {

	aps := r.Query(ctx, src, dst, sciond.PathReqFlags{})
	if filter != nil {
		aps = filter.Act(aps).(spathmeta.AppPathSet)
	}
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

	noPaths := len(aps) == 0
	waitDuration := r.getWaitDuration(noPaths)
	go func() {
		defer log.LogPanicAndExit()
		for {
			select {
			case <-closeC:
				return
			case <-time.After(waitDuration):
				ctx, cancelF := context.WithTimeout(context.Background(), DefaultQueryTimeout)
				flags := sciond.PathReqFlags{}
				// If there is a filter and there are no paths we set the refresh flag to get
				// more possible paths
				if noPaths && filter != nil {
					flags.Refresh = true
				}
				aps := r.Query(ctx, src, dst, flags)
				if filter != nil {
					aps = filter.Act(aps).(spathmeta.AppPathSet)
				}
				cancelF()
				sp.update(aps)
				noPaths = len(aps) == 0
				waitDuration = r.getWaitDuration(noPaths)
			}
		}
	}()
	return sp, nil
}

func (r *resolver) getWaitDuration(isError bool) time.Duration {
	if isError {
		return r.timers.ErrorRefire
	}
	return r.timers.NormalRefire
}

func (r *resolver) Watch(ctx context.Context, src, dst addr.IA) (*SyncPaths, error) {
	return r.WatchFilter(ctx, src, dst, nil)
}

func (r *resolver) WatchCount() int {
	return r.runningSyncPaths.Len()
}

func (r *resolver) RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes) {
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(rawSRevInfo)
	if err != nil {
		r.logger.Error("Revocation failed, unable to parse signed revocation info",
			"raw", rawSRevInfo, "err", err)
		return
	}
	r.Revoke(ctx, sRevInfo)
}

func (r *resolver) Revoke(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo) {
	reply, err := r.sciondConn.RevNotification(context.Background(), sRevInfo)
	if err != nil {
		r.logger.Error("Revocation failed, unable to inform SCIOND about revocation", "err", err)
		return
	}
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		r.logger.Error("Revocation failed, unable to parse revocation info",
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
			aps = dropRevoked(aps, pi)
			sp.update(aps)
		}
		r.runningSyncPaths.Apply(f)
	case sciond.RevStale:
		r.logger.Warn("Found stale revocation notification", "revInfo", revInfo)
	case sciond.RevInvalid:
		r.logger.Warn("Found invalid revocation notification", "revInfo", revInfo)
	}
}

func (r *resolver) Sciond() sciond.Connector {
	return r.sciondConn
}

func dropRevoked(aps spathmeta.AppPathSet, pi sciond.PathInterface) spathmeta.AppPathSet {
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

func getLogger(logger log.Logger) log.Logger {
	if logger != nil {
		logger = logger.New("lib", "PathResolver")
	}
	return log.Root()
}
