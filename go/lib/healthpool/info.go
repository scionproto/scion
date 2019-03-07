// Copyright 2019 Anapaya Systems
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

package healthpool

import (
	"math"
	"sync"
	"time"
)

// MaxFailCount is the maximum fail count for a health info.
const MaxFailCount = math.MaxUint16

// Info keeps track of the fails for a key. Implementations that want to
// use healthpool should embed this interface and initialize it with the
// constructor NewInfo. See healthpool/svcinstance for an example.
type Info interface {
	// Fail increases the fail count.
	Fail()
	// FailCount returns the fail count.
	FailCount() int
	// ResetCount resets the fail count to zero.
	ResetCount()
	// expireFails reduces the fail count.
	expireFails(now time.Time, opts ExpireOptions)
}

var _ Info = (*info)(nil)

// info is the private implementation for Info.
type info struct {
	mtx      sync.RWMutex
	lastFail time.Time
	lastExp  time.Time
	fails    uint16
}

// NewInfo creates a new health info.
func NewInfo() Info {
	return &info{
		lastFail: time.Now(),
		lastExp:  time.Now(),
	}
}

func (c *info) Fail() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lastFail = time.Now()
	if int(c.fails) < MaxFailCount {
		c.fails++
	}
}

func (c *info) FailCount() int {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return int(c.fails)
}

func (c *info) ResetCount() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.fails = 0
}

// expireFails exponentially reduces the fail count.
func (c *info) expireFails(now time.Time, opts ExpireOptions) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	expStart := max(c.lastFail.Add(opts.start()), c.lastExp.Add(opts.interval()))
	if now.Before(expStart) {
		return
	}
	c.fails >>= uint(now.Sub(expStart)/opts.interval()) + 1
	c.lastExp = now
}

func max(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
