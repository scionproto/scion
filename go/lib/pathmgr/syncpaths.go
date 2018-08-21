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
	"sync"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

// SyncPaths contains a concurrency-safe reference to an spathmeta.AppPathSet that is
// continuously kept up to date by the path manager.  Callers can safely `Load`
// the reference and use the paths within. At any moment, the path resolver can
// change the value of the reference within a SyncPaths to a different slice
// containing new paths. Calling code should reload the reference often to make
// sure the paths are fresh. Timestamp() can be called to get the time of the
// last write.
//
// A SyncPaths must never be copied.
type SyncPaths struct {
	value atomic.Value
	// Used to avoid races between multiple writers
	mutex sync.Mutex
}

// SyncPathsData is the atomic value inside a SyncPaths object. It provides a
// snapshot of a SyncPaths object. Callers must not change APS.
type SyncPathsData struct {
	APS         spathmeta.AppPathSet
	ModifyTime  time.Time
	RefreshTime time.Time
}

// NewSyncPaths creates a new SyncPaths object and sets the timestamp to
// current time.  A newly created SyncPaths contains a nil spathmeta.AppPathSet.
func NewSyncPaths() *SyncPaths {
	sp := &SyncPaths{}
	now := time.Now()
	sp.value.Store(
		&SyncPathsData{
			APS:         make(spathmeta.AppPathSet),
			ModifyTime:  now,
			RefreshTime: now,
		},
	)
	return sp
}

// update adds and removes paths in sp to match newAPS. If a path was added or
// removed, the modified timestamp is updated. The refresh timestamp is always
// updated.
// FIXME(scrye): Add SCIOND support s.t. the refresh timestamp is changed only
// when paths (including path metadata) change.
func (sp *SyncPaths) update(newAPS spathmeta.AppPathSet) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()
	value := sp.Load()
	value.RefreshTime = time.Now()
	toAdd := setSubtract(newAPS, value.APS)
	toRemove := setSubtract(value.APS, newAPS)
	if len(toAdd) > 0 || len(toRemove) > 0 {
		value.ModifyTime = value.RefreshTime
	}
	value.APS = newAPS
	sp.value.Store(value)
}

// Load returns a SyncPathsData snapshot of the data within sp.
func (sp *SyncPaths) Load() *SyncPathsData {
	val := *sp.value.Load().(*SyncPathsData)
	return &val
}

func setSubtract(x, y spathmeta.AppPathSet) spathmeta.AppPathSet {
	result := make(spathmeta.AppPathSet)
	for _, ap := range x {
		if _, ok := y[ap.Key()]; !ok {
			result.Add(ap.Entry)
		}
	}
	return result
}
