// Copyright 2018 Anapaya Systems
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

package discoverypool

import (
	"math"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/discovery/discoveryinfo"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ discovery.InstancePool = (*Pool)(nil)

// Pool maps discovery service instances to their info.
type Pool struct {
	mu sync.Mutex
	m  map[string]discovery.InstanceInfo
}

// New populates the pool with discovery service instances from the map
// in svcInfo. At least one instance must be present.
func New(svcInfo topology.IDAddrMap) (*Pool, error) {
	if len(svcInfo) <= 0 {
		return nil, common.NewBasicError(
			"SvcInfo must contain at least one discovery service instance", nil)
	}
	p := &Pool{
		m: make(map[string]discovery.InstanceInfo, len(svcInfo)),
	}
	p.Update(svcInfo)
	return p, nil
}

// Update adds missing instances and removes instances which are no longer in the topology.
func (p *Pool) Update(svcInfo topology.IDAddrMap) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Add missing DS servers.
	for k, v := range svcInfo {
		if info, ok := p.m[k]; !ok {
			p.m[k] = discoveryinfo.New(k, v.PublicAddr(v.Overlay))
		} else {
			info.Update(v.PublicAddr(v.Overlay))
		}
	}
	// Get list of outdated DS servers.
	var del []string
	for k := range p.m {
		if _, ok := svcInfo[k]; !ok {
			del = append(del, k)
		}
	}
	// Check that more than one DS remain.
	if len(del) == len(p.m) {
		return common.NewBasicError("Unable to delete all discovery service instances", nil)
	}
	for _, k := range del {
		delete(p.m, k)
	}
	return nil
}

// Choose returns the info for the discovery service instance with the
// minimal fail count in the pool.
func (p *Pool) Choose() (discovery.InstanceInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var best discovery.InstanceInfo
	var minFail = math.MaxUint16
	for _, ds := range p.m {
		failCount := ds.FailCount()
		if failCount < minFail {
			best = ds
			minFail = failCount
		}
	}
	if best == nil {
		return nil, common.NewBasicError("Unable to find any discovery service instance", nil)
	}
	return best, nil
}
