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

package memrevcache

import (
	"context"
	"sync"
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/revcache"
)

var _ revcache.RevCache = (*memRevCache)(nil)

type memRevCache struct {
	// Do not embed or use type directly to reduce the cache's API surface
	c    *cache.Cache
	lock sync.RWMutex
}

// New creates a new RevCache, backed by an in memory cache.
func New(defaultExpiration, cleanupInterval time.Duration) revcache.RevCache {
	return &memRevCache{
		c: cache.New(defaultExpiration, cleanupInterval),
	}
}

func (c *memRevCache) Get(ctx context.Context,
	k *revcache.Key) (*path_mgmt.SignedRevInfo, bool, error) {

	c.lock.RLock()
	defer c.lock.RUnlock()
	v, ok := c.get(k.String())
	return v, ok, nil
}

func (c *memRevCache) get(key string) (*path_mgmt.SignedRevInfo, bool) {
	obj, ok := c.c.Get(key)
	if !ok {
		return nil, false
	}
	return obj.(*path_mgmt.SignedRevInfo), true
}

func (c *memRevCache) GetAll(ctx context.Context,
	keys map[revcache.Key]struct{}) ([]*path_mgmt.SignedRevInfo, error) {

	c.lock.RLock()
	defer c.lock.RUnlock()
	revs := make([]*path_mgmt.SignedRevInfo, 0, len(keys))
	for k := range keys {
		if revInfo, ok := c.get(k.String()); ok {
			revs = append(revs, revInfo)
		}
	}
	return revs, nil
}

func (c *memRevCache) Insert(ctx context.Context, rev *path_mgmt.SignedRevInfo) (bool, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	newInfo, err := rev.RevInfo()
	if err != nil {
		panic(err)
	}
	ttl := newInfo.Expiration().Sub(time.Now())
	if ttl <= 0 {
		return false, nil
	}
	k := revcache.NewKey(newInfo.IA(), newInfo.IfID)
	key := k.String()
	val, ok := c.get(key)
	if !ok {
		c.c.Set(key, rev, ttl)
		return true, nil
	}
	existingInfo, err := val.RevInfo()
	if err != nil {
		panic(err)
	}
	if newInfo.Timestamp().After(existingInfo.Timestamp()) {
		c.c.Set(key, rev, ttl)
		return true, nil
	}
	return false, nil
}
