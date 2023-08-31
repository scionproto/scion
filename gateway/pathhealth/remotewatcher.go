// Copyright 2020 Anapaya Systems
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

package pathhealth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	// graceInterval specifies how long to keep unused paths around.
	graceInterval = time.Minute

	defaultPathFetchTimeout = 10 * time.Second
)

// PathWatcher monitors a specific path.
type PathWatcher interface {
	// Run runs the path watcher until the context is cancelled.
	Run(context.Context)
	// UpdatePath changes a path to be monitored. While actual path, as in
	// "sequence of SCION interfaces", must never change for a single
	// PathWatcher object, some elements of the path structure (e.g. expiration)
	// do change and should be updated accordingly.
	UpdatePath(path snet.Path)
	// Path returns a fresh copy of the monitored path.
	Path() snet.Path
	// State returns the state of the monitored path.
	State() State
}

// PathWatcherFactory constructs a PathWatcher.
type PathWatcherFactory interface {
	New(ctx context.Context, remote addr.IA, path snet.Path) (PathWatcher, error)
}

// DefaultRemoteWatcherFactory is a default factory for creating RemoteWatchers.
type DefaultRemoteWatcherFactory struct {
	// Router is used to find paths to remote ASes.
	Router interface {
		AllRoutes(ctx context.Context, dst addr.IA) ([]snet.Path, error)
	}
	// PathWatcherFactory is used to construct PathWatchers.
	PathWatcherFactory PathWatcherFactory
	// PathUpdateInterval specified how often the paths are retrieved from the
	// daemon. If not specified a default is used.
	PathUpdateInterval time.Duration
	// PathFetchTimeout is the timeout for the path fetch operation. If not set
	// a default value is used.
	PathFetchTimeout time.Duration
	// PathsMonitored is a gauge counting the number of paths currently
	// monitored to a remote AS.
	PathsMonitored func(remote addr.IA) metrics.Gauge
}

// New creates an RemoteWatcher that keeps track of all the paths for a given
// remote, and spawns/kills PathWatchers appropriately.
func (f *DefaultRemoteWatcherFactory) New(remote addr.IA) RemoteWatcher {
	var pathsMonitored metrics.Gauge
	if f.PathsMonitored != nil {
		pathsMonitored = f.PathsMonitored(remote)
	}
	return &remoteWatcher{
		remote:             remote,
		router:             f.Router,
		pathWatcherFactory: f.PathWatcherFactory,
		pathWatchers:       make(map[snet.PathFingerprint]*pathWatcherItem),
		// Set this to true so that first failure to get paths is logged.
		hasPaths:           true,
		pathUpdateInterval: f.PathUpdateInterval,
		pathFetchTimeout:   f.PathFetchTimeout,
		pathsMonitored:     pathsMonitored,
	}
}

type remoteWatcher struct {
	// remote is the ISD-AS of the monitored AS.
	remote addr.IA
	// router is used to find paths to remote ASes.
	router interface {
		AllRoutes(ctx context.Context, dst addr.IA) ([]snet.Path, error)
	}
	// pathWatcherFactory constructs a PathWatcher.
	pathWatcherFactory PathWatcherFactory
	// pathWatchersMtx protexts the pathWatcher maps
	pathWatcherMtx sync.Mutex
	// pathWatchers is a map of all the paths being currently monitored, indexed by path
	// fingerprint.
	pathWatchers map[snet.PathFingerprint]*pathWatcherItem
	// hasPaths is true if, at the moment, there is at least one path known.
	hasPaths bool

	// pathUpdateInterval specifies how often the paths are retrieved from the
	// daemon. If not set a default value is used.
	pathUpdateInterval time.Duration
	// pathFetchTimeout specifies the timeout for path lookup operations. If not
	// set a default value is used.
	pathFetchTimeout time.Duration

	pathsMonitored metrics.Gauge
}

func (w *remoteWatcher) Run(ctx context.Context) {
	w.initDefaults()
	ctx, _ = log.WithLabels(ctx, "remote_isd_as", w.remote.String())
	w.updatePaths(ctx)

	updateTicker := time.NewTicker(w.pathUpdateInterval)
	defer updateTicker.Stop()
	for {
		select {
		case <-updateTicker.C:
			w.updatePaths(ctx)
			w.cleanup(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (w *remoteWatcher) PathWatchers() []PathWatcher {
	w.pathWatcherMtx.Lock()
	defer w.pathWatcherMtx.Unlock()

	watchers := make([]PathWatcher, 0, len(w.pathWatchers))
	for _, entry := range w.pathWatchers {
		watchers = append(watchers, entry.pathWatcher)
	}
	return watchers
}

// cleanup stops monitoring paths that are not being used any more.
func (w *remoteWatcher) cleanup(ctx context.Context) {
	w.pathWatcherMtx.Lock()
	defer w.pathWatcherMtx.Unlock()

	for fingerprint, pm := range w.pathWatchers {
		if !pm.pathWatcher.State().IsExpired && pm.usedRecently() {
			continue
		}
		pm.cancel()
		delete(w.pathWatchers, fingerprint)
	}
	metrics.GaugeSet(w.pathsMonitored, float64(len(w.pathWatchers)))
}

func (w *remoteWatcher) initDefaults() {
	if w.pathUpdateInterval == 0 {
		w.pathUpdateInterval = defaultPathUpdateInterval
	}
	if w.pathFetchTimeout == 0 {
		w.pathFetchTimeout = defaultPathFetchTimeout
	}
}

func (w *remoteWatcher) updatePaths(ctx context.Context) {
	logger := log.FromCtx(ctx)
	now := time.Now()
	// Get the current set of paths from pathmgr.
	routerCtx, cancel := context.WithTimeout(ctx, w.pathFetchTimeout)
	defer cancel()
	paths, err := w.router.AllRoutes(routerCtx, w.remote)
	if err != nil {
		if w.hasPaths {
			logger.Info("Failed to get paths. Keeping old paths",
				"path_count", len(paths), "err", err)
			w.hasPaths = false
		}
		return
	}
	if len(paths) == 0 {
		if w.hasPaths {
			logger.Debug("No paths found")
			w.hasPaths = false
		}
		return
	}
	if !w.hasPaths {
		logger.Info("New paths discovered", "paths", len(paths))
		w.hasPaths = true
	}
	// Key the paths by their fingerprints.
	pathmap := make(map[snet.PathFingerprint]snet.Path)
	for _, path := range paths {
		pathmap[snet.Fingerprint(path)] = path
	}

	w.pathWatcherMtx.Lock()
	defer w.pathWatcherMtx.Unlock()

	// Updating paths is done in such a way that path statistics are preserved.
	for fingerprint, pw := range w.pathWatchers {
		// Mark any old entry that isn't present in the update for removal.
		if _, ok := pathmap[fingerprint]; !ok {
			pw.lastUsed = now
		}
	}
	for fingerprint, path := range pathmap {
		pw, ok := w.pathWatchers[fingerprint]
		if !ok {
			pathW, err := w.pathWatcherFactory.New(ctx, w.remote, path)
			if err != nil {
				logger.Error("Failed to create path watcher", "path", fmt.Sprint(path), "err", err)
				continue
			}
			pathWCtx, cancel := context.WithCancel(ctx)
			go func() {
				defer log.HandlePanic()

				pathW.Run(pathWCtx)
			}()
			// This is a new path, add an entry.
			pw = &pathWatcherItem{
				pathWatcher: pathW,
				cancel:      cancel,
			}
			w.pathWatchers[fingerprint] = pw
		} else {
			// If the path already exists, update it. Needed to keep expirations fresh.
			pw.pathWatcher.UpdatePath(path)
			pw.lastUsed = time.Time{}
		}
	}
	metrics.GaugeSet(w.pathsMonitored, float64(len(w.pathWatchers)))
}

// pathWatcherItem is an wrapper type that adds RemoteWatcher-specific data to pathWatcher.
type pathWatcherItem struct {
	pathWatcher PathWatcher
	// lastUsed is the time when the path ceased to be used.
	// If the path is used right now, set to time.Time{}.
	// Paths that are not used will be removed after a certain period of time.
	lastUsed time.Time
	// cancel can be used to cancel the running path watcher.
	cancel context.CancelFunc
}

// usedRecently returns true is the path is either being used or was used recently.
func (pm *pathWatcherItem) usedRecently() bool {
	// Keep paths that are used at the moment.
	if pm.lastUsed.IsZero() {
		return true
	}
	// Keep paths that have been used recently.
	if time.Since(pm.lastUsed) < graceInterval {
		return true
	}
	return false
}
