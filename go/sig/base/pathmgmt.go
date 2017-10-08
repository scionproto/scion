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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
)

type SyncPathPolicies struct {
	atomic.Value
}

func NewSyncPathPolicies() *SyncPathPolicies {
	spp := &SyncPathPolicies{}
	spp.Store(([]*PathPolicy)(nil))
	return spp
}

func (spp *SyncPathPolicies) Load() []*PathPolicy {
	return spp.Value.Load().([]*PathPolicy)
}

// PathPolicy contains the path policy for a given remote AS. This means having
// a pool of paths that match the specified policy, metrics about those paths,
// as well as maintaining the currently favoured path and remote SIG to use.
type PathPolicy struct {
	IA     *addr.ISD_AS
	policy interface{} // FIXME(kormat): not implemented yet :P
	//Policy  pathmgr.Policy // Describes what interfaces to route through
	pool     *pathmgr.SyncPaths // pool of paths that meet the policy requirement, managed by pathmgr
	currPath atomic.Value       // Currently favoured *sciond.PathReplyEntry
	currSig  atomic.Value       // Currently favoured *SIGInfo
	// Metrics per set of path hops, entries added/removed whenever pool changes.
	PathsMetrics map[pathmgr.PathKey]PathMetrics
	ring         *ringbuf.Ring
}

func NewPathPolicy(dstIA *addr.ISD_AS, currSig *SIGEntry, policy interface{}) (*PathPolicy, error) {
	var err error
	pp := &PathPolicy{IA: dstIA, policy: policy}
	// FIXME(kormat): change to `RegisterFilter once pathmgr supports policies.
	pp.pool, err = sigcmn.PathMgr.Register(sigcmn.IA, dstIA)
	if err != nil {
		return nil, err
	}
	// Initialize currPath
	var pathEntry *sciond.PathReplyEntry
	aps := pp.pool.Load()
	if aps != nil {
		ap := aps.GetAppPath()
		if ap != nil {
			pathEntry = ap.Entry
		}
	}
	pp.currPath.Store(pathEntry)
	// Initialize currSig
	pp.currSig.Store(currSig)
	pp.ring = ringbuf.New(64, nil, "egress", prometheus.Labels{"ringId": dstIA.String()})
	return pp, nil
}

func (pp *PathPolicy) CurrPath() *sciond.PathReplyEntry {
	return pp.currPath.Load().(*sciond.PathReplyEntry)
}

func (pp *PathPolicy) CurrSig() *SIGEntry {
	return pp.currSig.Load().(*SIGEntry)
}

func (pp *PathPolicy) Cleanup() error {
	pp.ring.Close()
	return nil
}

type PathMetrics struct {
	// Some statistics about latency and loss
}
