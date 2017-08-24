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

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

const (
	// maximum number of IAs that can be registered for priority tracking
	queryChanCap uint64 = 1 << 10
	// the number of max paths requested in each SCIOND query
	numReqPaths = 5
	// time between reconnection attempts if SCIOND fails
	reconnectInterval = 3 * time.Second
)

// query contains the context needed to issue and update a query
type query struct {
	src, dst *addr.ISD_AS
	sp       *SyncPaths
}

// SyncPaths contains a concurrency-safe reference to a slice `[]*PathReplyEntry`.
// Callers can safely `Load` the reference and use the paths within. At any
// moment, the path resolver can change the value of the reference within a
// SyncPaths to a different slice containing new paths. Calling code should
// reload the reference often to make sure the paths are fresh.
type SyncPaths struct {
	atomic.Value
}

// Overwrite Load to avoid external type assertions
func (sp *SyncPaths) Load() []*sciond.PathReplyEntry {
	return sp.Value.Load().([]*sciond.PathReplyEntry)
}

// sciondState is used to track the health of the connection to SCIOND
type sciondState uint64

const (
	// SCIOND is considered down due to a query failing at network level
	sciondDown sciondState = iota
	// SCIOND is considered up
	sciondUp
)

func (state sciondState) String() string {
	switch state {
	case sciondDown:
		return "down"
	case sciondUp:
		return "up"
	default:
		return "unknown"
	}
}
