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

package info

import (
	"math"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ discovery.Pool = (*Pool)(nil)

// Pool maps discovery service to their info.
type Pool struct {
	mu sync.Mutex
	m  map[string]*Info
}

// NewPool populates the pool with discovery service entries from the topo.
// At least one service must be present.
func NewPool(topo *topology.Topo) (*Pool, error) {
	if len(topo.DS) <= 0 {
		return nil, common.NewBasicError("Topo must contain DS address", nil)
	}
	p := &Pool{
		m: make(map[string]*Info, len(topo.DS)),
	}
	p.Update(topo)
	return p, nil
}

// Update adds missing services from the topo and removes services which
// are no longer in the topo.
func (p *Pool) Update(topo *topology.Topo) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Add missing DS servers.
	for k, v := range topo.DS {
		if info, ok := p.m[k]; !ok {
			p.m[k] = &Info{
				key:      k,
				addr:     v.PublicAddr(topo.Overlay),
				lastFail: time.Now(),
				lastExp:  time.Now(),
			}
		} else {
			info.Update(v.PublicAddr(topo.Overlay))
		}
	}
	// Get list of outdated DS servers.
	var del []string
	for k := range p.m {
		if _, ok := topo.DS[k]; !ok {
			del = append(del, k)
		}
	}
	// Check that more than one DS remain.
	if len(del) == len(p.m) {
		return common.NewBasicError("Unable to delete all discovery services", nil)
	}
	for _, k := range del {
		delete(p.m, k)
	}
	return nil
}

// Choose returns the info for the discovery service with the
// minimal fail count in the pool.
func (p *Pool) Choose() (discovery.Info, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var r *Info
	var minFail = math.MaxUint16
	for _, ds := range p.m {
		failCount := ds.FailCount()
		if failCount < minFail {
			r = ds
			minFail = failCount
		}
	}
	if r == nil {
		return nil, common.NewBasicError("Unable to find discovery service", nil)
	}
	return r, nil
}
