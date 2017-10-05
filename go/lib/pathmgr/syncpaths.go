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
	"sync/atomic"
	"time"
)

// SyncPaths contains a concurrency-safe reference to an AppPathSet that is
// continuously kept up to date by the path manager.  Callers can safely `Load`
// the reference and use the paths within. At any moment, the path resolver can
// change the value of the reference within a SyncPaths to a different slice
// containing new paths. Calling code should reload the reference often to make
// sure the paths are fresh. Timestamp() can be called to get the time of the
// last write.
//
// A SyncPaths must never be copied.
type SyncPaths struct {
	value     atomic.Value
	timestamp atomic.Value
}

// NewSyncPaths creates a new SyncPaths object and sets the timestamp to
// current time.  A newly created SyncPaths contains a nil AppPathSet.
func NewSyncPaths() *SyncPaths {
	sp := &SyncPaths{}
	sp.timestamp.Store(time.Now())
	sp.Store(AppPathSet(nil))
	return sp
}

// Store atomically updates the AppPathSet and refreshes the timestamp
func (sp *SyncPaths) Store(aps AppPathSet) {
	sp.value.Store(aps)
	// This races with the above when multiple callers use Store, but the time
	// will be close enough that we don't mind.
	sp.timestamp.Store(time.Now())
}

// Load returns a reference to the AppPathSet within.
func (sp *SyncPaths) Load() AppPathSet {
	return sp.value.Load().(AppPathSet)
}

// Timestamp returns the time of the last Store to sp
func (sp *SyncPaths) Timestamp() time.Time {
	return sp.timestamp.Load().(time.Time)
}
