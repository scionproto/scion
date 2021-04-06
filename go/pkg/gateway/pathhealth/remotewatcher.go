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
	"math/rand"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// graceInterval specifies how long to keep unused paths around.
	graceInterval = time.Minute
	// routerTimeout is a timeout for querying the paths via snet.Router.
	// TODO(sustrik): Given that path querying and path fetching is done in the same
	// thread, let's set this to probeInterval - 100ms. Eventually, the two tasks
	// should run in two separate goroutines.
	routerTimeout = 400 * time.Millisecond
)

// PathWatcher monitors a specific path.
type PathWatcher interface {
	// UpdatePath changes a path to be monitored. While actual path, as in
	// "sequence of SCION interfaces", must never change for a single
	// PathWatcher object, some elements of the path structure (e.g. expiration)
	// do change and should be updated accordingly.
	UpdatePath(path snet.Path)
	// SendProbe sends a probe along the monitored path.
	SendProbe(conn snet.PacketConn, localAddr snet.SCIONAddress)
	// HandleProbeReply dispatches a single probe reply packet.
	HandleProbeReply(seq uint16)
	// Path returns a fresh copy of the monitored path.
	Path() snet.Path
	// State returns the state of the monitored path.
	State() State
	// Close stops the PathWatcher.
	Close()
}

// PathWatcherFactory constructs a PathWatcher.
type PathWatcherFactory interface {
	New(remote addr.IA, path snet.Path, id uint16) PathWatcher
}

// DefaultRemoteWatcherFactory is a default factory for creating RemoteWatchers.
type DefaultRemoteWatcherFactory struct {
	// PathWatcherFactory is used to construct PathWatchers.
	PathWatcherFactory PathWatcherFactory
	// Logger is the parent logger. If nil, the RemoteWatcher is constructed without
	// any logger.
	Logger log.Logger
	// PathsMonitored is a gauge counting the number of paths currently
	// monitored to a remote AS.
	PathsMonitored metrics.Gauge
	// ProbesSent keeps track of how many path probes have been sent per remote AS.
	ProbesSent metrics.Counter
	// ProbesReceived keeps track of how many path probes have been received per remote AS.
	ProbesReceived metrics.Counter
}

// New creates an RemoteWatcher that keeps track of all the paths for a given
// remote, and spawns/kills PathWatchers appropriately.
func (f *DefaultRemoteWatcherFactory) New(remote addr.IA) RemoteWatcher {
	var logger log.Logger
	if f.Logger != nil {
		logger = f.Logger.New("isd_as", remote)
	}
	return &DefaultRemoteWatcher{
		remote:             remote,
		pathWatcherFactory: f.PathWatcherFactory,
		pathWatchers:       make(map[snet.PathFingerprint]*pathWatcherItem),
		pathWatchersByID:   make(map[uint16]*pathWatcherItem),
		logger:             logger,
		pathsMonitored:     metrics.GaugeWith(f.PathsMonitored, "remote_isd_as", remote.String()),
		probesSent:         metrics.CounterWith(f.ProbesSent, "remote_isd_as", remote.String()),
		probesReceived:     metrics.CounterWith(f.ProbesReceived, "remote_isd_as", remote.String()),
		// Set this to true so that first failure to get paths is logged.
		hasPaths: true,
	}
}

// DefaultRemoteWatcher monitors a remote IA.
type DefaultRemoteWatcher struct {
	// remote is the ISD-AS of the monitored AS.
	remote addr.IA
	// pathWatcherFactory constructs a PathWatcher.
	pathWatcherFactory PathWatcherFactory
	// pathWatchersMtx protexts the pathWatcher maps
	pathWatcherMtx sync.Mutex
	// pathWatchers is a map of all the paths being currently monitored, indexed by path
	// fingerprint.
	pathWatchers map[snet.PathFingerprint]*pathWatcherItem
	// pathWatchersByID contains the same paths as above, but indexed by SCMP Echo ID.
	pathWatchersByID map[uint16]*pathWatcherItem
	// hasPaths is true if, at the moment, there is at least one path known.
	hasPaths bool

	logger         log.Logger
	pathsMonitored metrics.Gauge
	probesSent     metrics.Counter
	probesReceived metrics.Counter
}

// UpdatePaths gets new paths from the SCION daemon. This function may block for
// up to routerTimeout.
func (w *DefaultRemoteWatcher) UpdatePaths(router snet.Router) {
	now := time.Now()
	// Get the current set of paths from pathmgr.
	ctx, cancel := context.WithTimeout(context.Background(), routerTimeout)
	defer cancel()
	paths, err := router.AllRoutes(ctx, w.remote)
	if err != nil {
		if w.hasPaths {
			log.SafeInfo(w.logger, "Failed to get paths. Keeping old paths",
				"path_count", len(paths), "err", err)
			w.hasPaths = false
		}
		return
	}
	if len(paths) == 0 {
		if w.hasPaths {
			log.SafeDebug(w.logger, "No paths found")
			w.hasPaths = false
		}
		return
	}
	if !w.hasPaths {
		log.SafeInfo(w.logger, "New paths discovered", "paths", len(paths))
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
			id, found := w.selectID()
			if !found {
				log.SafeInfo(w.logger, "All traceroute IDs are occupied")
				continue
			}

			// This is a new path, add an entry.
			pw = &pathWatcherItem{
				PathWatcher: w.pathWatcherFactory.New(w.remote, path, id),
			}
			w.pathWatchers[fingerprint] = pw
			w.pathWatchersByID[id] = pw
		} else {
			// If the path already exists, update it. Needed to keep expirations fresh.
			pw.UpdatePath(path)
			pw.lastUsed = time.Time{}
		}
	}
	metrics.GaugeSet(w.pathsMonitored, float64(len(w.pathWatchers)))
}

// SendProbes sends probes via all the available paths to the monitored IA.
func (w *DefaultRemoteWatcher) SendProbes(conn snet.PacketConn, localAddr snet.SCIONAddress) {
	w.pathWatcherMtx.Lock()
	defer w.pathWatcherMtx.Unlock()

	metrics.CounterAdd(w.probesSent, float64(len(w.pathWatchers)))
	for _, pm := range w.pathWatchers {
		pm.SendProbe(conn, localAddr)
	}
}

// HandleProbeReply dispatches a single probe reply packet.
func (w *DefaultRemoteWatcher) HandleProbeReply(id, seq uint16) {
	w.pathWatcherMtx.Lock()
	defer w.pathWatcherMtx.Unlock()

	metrics.CounterInc(w.probesReceived)
	pm, ok := w.pathWatchersByID[id]
	if !ok {
		log.SafeDebug(w.logger, "unsolicited reply (path no longer monitored)", "id", id)
		// Probe reply for a path that is no longer monitored.
		return
	}
	pm.HandleProbeReply(seq)
}

// Cleanup stops monitoring paths that are not being used any more.
func (w *DefaultRemoteWatcher) Cleanup() {
	w.pathWatcherMtx.Lock()
	defer w.pathWatcherMtx.Unlock()

	for fingerprint, pm := range w.pathWatchers {
		if !pm.State().IsExpired && pm.usedRecently() {
			continue
		}
		pm.Close()
		delete(w.pathWatchers, fingerprint)
		delete(w.pathWatchersByID, pm.id)
	}
	metrics.GaugeSet(w.pathsMonitored, float64(len(w.pathWatchers)))
}

// Watchers returns a list of all active PathWatchers.
func (w *DefaultRemoteWatcher) Watchers() []PathWatcher {
	w.pathWatcherMtx.Lock()
	defer w.pathWatcherMtx.Unlock()

	watchers := make([]PathWatcher, 0, len(w.pathWatchers))
	for _, entry := range w.pathWatchers {
		watchers = append(watchers, entry.PathWatcher)
	}
	return watchers
}

func (w *DefaultRemoteWatcher) selectID() (uint16, bool) {
	for i := 0; i < 100; i++ {
		id := uint16(rand.Uint32())
		if _, ok := w.pathWatchersByID[id]; !ok {
			return id, true
		}
	}
	return 0, false
}

// pathWatcherItem is an wrapper type that adds RemoteWatcher-specific data to pathWatcher.
type pathWatcherItem struct {
	PathWatcher
	id uint16
	// lastUsed is the time when the path ceased to be used.
	// If the path is used right now, set to time.Time{}.
	// Paths that are not used will be removed after a certain period of time.
	lastUsed time.Time
}

// usedRecently returns true is the path is either being used or was used recently.
func (pm *pathWatcherItem) usedRecently() bool {
	// Keep paths that are used at the moment.
	if pm.lastUsed.IsZero() {
		return true
	}
	// Keep paths that have been used recently.
	if time.Now().Sub(pm.lastUsed) < graceInterval {
		return true
	}
	return false
}
