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

package base

import (
	"sync/atomic"

	"github.com/netsec-ethz/scion/go/lib/pathmgr"
)

// PathPolicy contains the path policy for a given remote AS. This means having
// a pool of paths that match the specified policy, metrics about those paths,
// as well as maintaining the currently favoured path and remote SIG to use.
type PathPolicy struct {
	//Policy  pathmgr.Policy // Describes what interfaces to route through
	Pool    *pathmgr.SyncPaths // Pool of paths that meet the policy requirement, managed by pathmgr
	CurPath atomic.Value       // Currently favoured *pathmgr.AppPath
	CurSIG  atomic.Value       // Currently favoured *SIGInfo
	// Metrics per set of path hops, entries added/removed whenever Pool changes.
	PathsMetrics map[pathmgr.PathKey]PathMetrics
}

type PathMetrics struct {
	// Some statistics about latency and loss
}
