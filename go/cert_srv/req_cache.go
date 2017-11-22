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

package main

import (
	"sync"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/netsec-ethz/scion/go/lib/snet"
)

// ReqCache keeps track of requester addresses associated with a certain request key.
type ReqCache struct {
	// lock is the lock for synchronizing access cache.
	lock sync.Mutex
	// cache is an expiring cache for pending requests.
	cache *cache.Cache
	// delta is the minimal time between two requests for the same key.
	delta time.Duration
}

// NewReqCache creates a new request cache. Expire denotes the time until an entry expires.
// Cleanup denotes the cleanup interval. Delta is the minimal time between two requests for the same
// key.
func NewReqCache(expire, cleanup, delta time.Duration) *ReqCache {
	return &ReqCache{cache: cache.New(expire, cleanup), delta: delta}
}

// Put adds an address to the expiring cache. The return value indicates whether the delta has
// passed and the caller should issue a new request.
func (c *ReqCache) Put(key string, addr *snet.Addr) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	val, ok := c.cache.Get(key)
	if !ok {
		val = &AddrSet{Addrs: make(map[string]*snet.Addr)}
		c.cache.SetDefault(key, val)
	}
	reqs := val.(*AddrSet)
	reqs.Addrs[addr.String()] = addr.Copy()
	if reqs.LastReq.Add(c.delta).Before(time.Now()) {
		reqs.LastReq = time.Now()
		return true
	}
	return false
}

// Pop returns the AddrSet for a specified key and removes the entry from the cache.
func (c *ReqCache) Pop(key string) *AddrSet {
	c.lock.Lock()
	defer c.lock.Unlock()
	val, ok := c.cache.Get(key)
	if ok {
		c.cache.Delete(key)
		return val.(*AddrSet)
	}
	return nil
}

// AddrSet is a struct holding the requester addresses of a pending request and
// the timestamp, when the last request was sent for rate limiting.
type AddrSet struct {
	// Addrs is a set of addresses for an pending request.
	Addrs map[string]*snet.Addr
	// LastReq is a timestamp when the last request has been issued.
	LastReq time.Time
}
