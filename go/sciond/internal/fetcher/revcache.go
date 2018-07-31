// Copyright 2018 ETH Zurich, Anapaya Systems
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

package fetcher

import (
	"sync"
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/revcache"
)

var _ revcache.RevCache = (*RevCache)(nil)

type RevCache struct {
	// Do not embed or use type directly to reduce the cache's API surface
	c    *cache.Cache
	lock sync.RWMutex
}

func NewRevCache(defaultExpiration, cleanupInterval time.Duration) revcache.RevCache {
	return &RevCache{
		c: cache.New(defaultExpiration, cleanupInterval),
	}
}

func (c *RevCache) Get(k *revcache.Key) (*path_mgmt.SignedRevInfo, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	obj, ok := c.c.Get(k.String())
	if !ok {
		return nil, false
	}
	return obj.(*path_mgmt.SignedRevInfo), true
}

func (c *RevCache) Set(k *revcache.Key, rev *path_mgmt.SignedRevInfo, ttl time.Duration) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	key := k.String()
	_, exp, ok := c.c.GetWithExpiration(key)
	// If not yet in cache set, otherwise update expiry if it is later than current one.
	if !ok || time.Now().Add(ttl).After(exp) {
		c.c.Set(key, rev, ttl)
		return true
	}
	return false
}
