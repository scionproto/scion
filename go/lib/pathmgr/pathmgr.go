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
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
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

func (timers *Timers) GetWait(isError bool) time.Duration {
	if isError {
		return timers.ErrorRefire
	}
	return timers.NormalRefire
}

const (
	// DefaultNormalRefire is the wait time after a successful path lookup (for periodic lookups)
	DefaultNormalRefire = 10 * time.Second
	// DefaultErorrRefire is the wait time after a failed path lookup (for periodic lookups)
	DefaultErrorRefire = time.Second
	// DefaultQueryTimeout is the time allocated for a query to SCIOND
	DefaultQueryTimeout = 5 * time.Second
	// DefaultPathCount is the maximum number of paths returned to the user.
	DefaultPathCount = 5
)

// Policy is used to filter paths
type Policy interface {
	Filter(pathpol.PathSet) pathpol.PathSet
}

type Querier interface {
	// Query returns a set of paths between src and dst.
	Query(ctx context.Context, src, dst addr.IA, flags sciond.PathReqFlags) spathmeta.AppPathSet
}

type Resolver interface {
	Querier
	// QueryFilter returns a set of paths between src and dst that satisfy
	// policy. A nil policy will not delete any paths.
	QueryFilter(ctx context.Context, src, dst addr.IA, policy Policy) spathmeta.AppPathSet
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
	// lifetime or until Destroy is called on the SyncPaths object.
	Watch(ctx context.Context, src, dst addr.IA) (*SyncPaths, error)
	// WatchFilter returns a pointer to a SyncPaths object that contains paths from
	// src to dst that adhere to the specified filter. On path changes the list is
	// refreshed automatically.
	//
	// A nil filter will not delete any paths.
	WatchFilter(ctx context.Context, src, dst addr.IA, filter Policy) (*SyncPaths, error)
	// WatchCount returns the number of active watchers.
	WatchCount() int
	// RevokeRaw informs SCIOND of a revocation.
	RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes)
	// Revoke informs SCIOND of a revocation.
	Revoke(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo)
}

type resolver struct {
	sciondConn   sciond.Connector
	timers       Timers
	watchFactory *WatchFactory
	pathCount    uint16
}

// New creates a new path management context.
//
// Parameter timers can be used to customize path manager behavior; if any
// timer is left uninitialized, it is assigned the corresponding default value
// (see package constants). When a query for a path older than maxAge reaches
// the resolver, SCIOND is used to refresh the path. New returns with an error
// if a connection to SCIOND could not be established.
func New(conn sciond.Connector, timers Timers, pathCount uint16) Resolver {
	timers.initDefaults()
	if pathCount == 0 {
		pathCount = DefaultPathCount
	}
	r := &resolver{
		sciondConn:   conn,
		timers:       timers,
		watchFactory: NewWatchFactory(timers),
		pathCount:    pathCount,
	}
	return r
}

func (r *resolver) Query(ctx context.Context, src, dst addr.IA,
	flags sciond.PathReqFlags) spathmeta.AppPathSet {

	if flags.PathCount == 0 {
		flags.PathCount = r.pathCount
	}
	paths, err := r.sciondConn.Paths(ctx, dst, src, flags)
	if err != nil {
		r.logger(ctx).Error("SCIOND network error", "err", err)
		return make(spathmeta.AppPathSet)
	}
	return spathmeta.NewAppPathSet(paths)
}

func (r *resolver) QueryFilter(ctx context.Context, src, dst addr.IA,
	policy Policy) spathmeta.AppPathSet {

	aps := r.Query(ctx, src, dst, sciond.PathReqFlags{})
	if policy == nil {
		return aps
	}
	return psToAps(policy.Filter(apsToPs(aps)))
}

func (r *resolver) WatchFilter(ctx context.Context, src, dst addr.IA,
	filter Policy) (*SyncPaths, error) {

	aps := r.Query(ctx, src, dst, sciond.PathReqFlags{})
	if filter != nil {
		aps = psToAps(filter.Filter(apsToPs(aps)))
	}
	sp := NewSyncPaths()
	sp.Update(aps)

	query := &queryConfig{
		querier: Querier(r),
		src:     src,
		dst:     dst,
		filter:  filter,
	}
	pp := NewPollingPolicy(filter != nil, r.timers)
	w := r.watchFactory.New(sp, query, pp)
	sp.setDestructor(w.Destroy)

	go func() {
		defer log.HandlePanic()
		w.Run()
	}()
	return sp, nil
}

func (r *resolver) Watch(ctx context.Context, src, dst addr.IA) (*SyncPaths, error) {
	return r.WatchFilter(ctx, src, dst, nil)
}

func (r *resolver) WatchCount() int {
	return r.watchFactory.length()
}

func (r *resolver) RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes) {
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(rawSRevInfo)
	if err != nil {
		r.logger(ctx).Error("Revocation failed, unable to parse signed revocation info",
			"raw", rawSRevInfo, "err", err)
		return
	}
	r.Revoke(ctx, sRevInfo)
}

func (r *resolver) Revoke(ctx context.Context, sRevInfo *path_mgmt.SignedRevInfo) {
	logger := r.logger(ctx)
	reply, err := r.sciondConn.RevNotification(context.Background(), sRevInfo)
	if err != nil {
		logger.Error("Revocation failed, unable to inform SCIOND about revocation", "err", err)
		return
	}
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		logger.Error("Revocation failed, unable to parse revocation info",
			"sRevInfo", sRevInfo, "err", err)
		return
	}
	switch reply.Result {
	case sciond.RevUnknown, sciond.RevValid:
		// Each watcher contains a cache; purge paths matched by the revocation
		// immediately from each cache.
		pi := sciond.PathInterface{RawIsdas: revInfo.IA().IAInt(),
			IfID: common.IFIDType(revInfo.IfID)}
		f := func(w *WatchRunner) {
			pathsBeforeRev := w.sp.Load().APS
			pathsAfterRev := dropRevoked(pathsBeforeRev, pi)
			w.sp.Update(pathsAfterRev)
			if len(pathsAfterRev) == 0 && len(pathsBeforeRev) > 0 {
				w.pp.PollNow()
			}
		}
		r.watchFactory.apply(f)
	case sciond.RevStale:
		logger.Info("Found stale revocation notification", "revInfo", revInfo)
	case sciond.RevInvalid:
		logger.Info("Found invalid revocation notification", "revInfo", revInfo)
	}
}

func (r *resolver) logger(ctx context.Context) log.Logger {
	return log.FromCtx(ctx).New("lib", "PathResolver")
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

func matches(path snet.Path, predicatePI sciond.PathInterface) bool {
	for _, pi := range path.Interfaces() {
		if pi.IA().Equal(predicatePI.IA()) && pi.ID() == predicatePI.ID() {
			return true
		}
	}
	return false
}

func apsToPs(aps spathmeta.AppPathSet) pathpol.PathSet {
	ps := make(pathpol.PathSet, len(aps))
	for key, path := range aps {
		ps[key] = path
	}
	return ps
}

func psToAps(ps pathpol.PathSet) spathmeta.AppPathSet {
	aps := make(spathmeta.AppPathSet)
	for key, path := range ps {
		aps[key] = path.(snet.Path)
	}
	return aps
}
