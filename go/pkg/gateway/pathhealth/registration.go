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
	"sync"

	"github.com/scionproto/scion/go/lib/snet"
)

// State is the path state used during selection.
type State struct {
	// IsAlive indicates that the path is currently alive.
	IsAlive bool
	// IsExpired indicates that the path is expired. IsExpired == true implies IsAlive == false but
	// not vice versa.
	IsExpired bool
}

// Selectable is a subset of the PathWatcher that is used for path selection.
type Selectable interface {
	Path() snet.Path
	State() State
}

// FingerprintSet is a set of path fingerprints.
type FingerprintSet map[snet.PathFingerprint]struct{}

// PathSelector selects the best paths from all the available path watchers.
type PathSelector interface {
	Select(selectable []Selectable, current FingerprintSet) Selection
}

// Selection contains the set of selected paths with metadata.
type Selection struct {
	// Path is the list of selected paths. The list is sorted from best to worst
	// according to the scoring function used by the selector.
	Paths []snet.Path
	// Info is an info string providing more info about why the path was selected.
	Info string
	// PathsAlive is the number of active paths available.
	PathsAlive int
	// PathsDead is the number of dead paths.
	PathsDead int
	// PathsRejected is the number of paths that are rejected by the policy.
	PathsRejected int
}

// Registration represents a single remote IA monitoring registration
type Registration struct {
	mu sync.Mutex
	// monitor is the PathMonitor instance this registration belongs to.
	monitor *Monitor
	// remoteWatcher points to the AS being monitored.
	remoteWatcher *remoteWatcherItem
	// currentFingerprints refer to the currently used paths.
	currentFingerprints FingerprintSet
	// pathSelector selects the paths.
	pathSelector PathSelector
}

// Get returns your own copy of the best available path.
func (r *Registration) Get() Selection {
	r.mu.Lock()
	defer r.mu.Unlock()

	watchers := r.remoteWatcher.Watchers()
	selectables := make([]Selectable, len(watchers))
	for i := range watchers {
		selectables[i] = watchers[i]
	}

	selection := r.pathSelector.Select(selectables, r.currentFingerprints)
	r.currentFingerprints = make(FingerprintSet)
	for _, path := range selection.Paths {
		r.currentFingerprints[snet.Fingerprint(path)] = struct{}{}
	}
	return selection
}

// Close cancels the registration.
func (r *Registration) Close() {
	r.monitor.unregister(r.remoteWatcher)
	// Remove the pointers so that the objects can be immediately GC'd.
	r.monitor = nil
	r.remoteWatcher = nil
}
