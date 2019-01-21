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

package discoveryinfo

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/discovery"
)

const (
	// failExpStart is the time after which fails are expired.
	failExpStart = 5 * time.Minute
	// failExpInterval is the interval between fail expiration.
	failExpInterval = 10 * time.Second
)

var _ discovery.InstanceInfo = (*Info)(nil)

// Info keeps track of the discovery service and its health.
type Info struct {
	mu        sync.Mutex
	addr      *addr.AppAddr
	key       string
	lastFail  time.Time
	lastExp   time.Time
	failCount uint16
}

// New creates a new info with the specified key and address.
func New(key string, addr *addr.AppAddr) *Info {
	return &Info{
		addr:     addr,
		key:      key,
		lastFail: time.Now(),
		lastExp:  time.Now(),
	}
}

// Update updates the address. If changed, the fail count is reset.
func (h *Info) Update(a *addr.AppAddr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !a.Equal(h.addr) {
		h.addr = a.Copy()
		h.failCount = 0
		h.lastFail = time.Now()
		h.lastExp = time.Now()
	}
}

// Key returns the info key.
func (h *Info) Key() string {
	return h.key
}

// Addr returns the address of the discovery service instance.
func (h *Info) Addr() *addr.AppAddr {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addr.Copy()
}

// FailCount returns the fail count.
func (h *Info) FailCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expireFails(time.Now())
	return int(h.failCount)
}

// Fail adds to the fail count.
func (h *Info) Fail() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expireFails(time.Now())
	h.lastFail = time.Now()
	if h.failCount < math.MaxInt16 {
		h.failCount++
	}
}

// expireFails reduces the fail count if the last fail is sufficiently long in the past.
// The caller is assumed to hold the lock on h.
func (h *Info) expireFails(now time.Time) {
	if now.Sub(h.lastFail) > failExpStart && now.Sub(h.lastExp) > failExpInterval {
		for i := 0; i < int(now.Sub(h.lastExp)/failExpInterval); i++ {
			h.failCount /= 2
		}
		h.lastExp = now
	}
}

func (h *Info) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return fmt.Sprintf("Key: %s lastFail: %s failCount: %d", h.key, h.lastFail, h.failCount)
}
