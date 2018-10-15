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

package discovery

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	// failExpStart is the time after which fails are expired.
	failExpStart = 5 * time.Minute
	// failExpInterval is the interval between fail expiration.
	failExpInterval = 10 * time.Second
)

// Pool maps discovery service to their info.
type Pool map[string]*Info

// NewPool populates the pool with discovery service entries from the topo.
// At least one service must be present.
func NewPool(topo *topology.Topo) (Pool, error) {
	if len(topo.DS) <= 0 {
		return nil, common.NewBasicError("Topo must contain DS address", nil)
	}
	pool := make(Pool)
	for k, v := range topo.DS {
		pool[k] = &Info{
			key:      k,
			addr:     v.PublicAddr(topo.Overlay),
			lastFail: time.Now(),
		}
	}
	return pool, nil
}

// Update adds missing services from the topo and removes services which
// are no longer in the topo.
func (p Pool) Update(topo *topology.Topo) error {
	// Add missing DS servers.
	for k, v := range topo.DS {
		if info, ok := p[k]; !ok {
			p[k] = &Info{
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
	for k := range p {
		if _, ok := topo.DS[k]; !ok {
			del = append(del, k)
		}
	}
	// Check that more than one DS remain.
	if len(del) == len(p) {
		return common.NewBasicError("Unable to delete all DS servers", nil)
	}
	for _, k := range del {
		delete(p, k)
	}
	return nil
}

// Choose returns the info for the discovery service with the
// minimal fail count in the pool.
func (p Pool) Choose() (*Info, error) {
	var r *Info
	var minFail uint16 = math.MaxUint16
	for _, ds := range p {
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

// Info keeps track of the discovery service and its health.
type Info struct {
	mu        sync.Mutex
	addr      *addr.AppAddr
	key       string
	lastFail  time.Time
	lastExp   time.Time
	failCount uint16
}

// Update updates the address. If changed, the fail count is reset.
func (h *Info) Update(a *addr.AppAddr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !a.Eq(h.addr) {
		h.addr = a.Copy()
		h.failCount = 0
		h.lastFail = time.Now()
		h.lastExp = time.Now()
	}
}

// Addr returns the address of the discovery service.
func (h *Info) Addr() *addr.AppAddr {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addr.Copy()
}

// FailCount returns the fail count.
func (h *Info) FailCount() uint16 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expireFails(time.Now())
	return h.failCount
}

// Fail adds to the fail count.
func (h *Info) Fail() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expireFails(time.Now())
	h.lastFail = time.Now()
	if h.failCount < math.MaxInt16 {
		h.failCount += 1
	}
}

// expireFails reduces the fail count if the last fail is sufficiently long in the past.
// The caller is assumed to hold the lock on h.
func (h *Info) expireFails(now time.Time) {
	if now.Sub(h.lastFail) > failExpStart && now.Sub(h.lastExp) > failExpInterval {
		h.failCount /= 2
		h.lastExp = now
	}
}

func (h *Info) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return fmt.Sprintf("Key: %s lastFail: %s failCount: %d", h.key, h.lastFail, h.failCount)
}
