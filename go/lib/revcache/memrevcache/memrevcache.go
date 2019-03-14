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
func New() *memRevCache {
	return &memRevCache{
		// We insert all the items with expiration so no need to have a default expiration.
		// The cleaning should happen manually using the DeleteExpired method.
		c: cache.New(cache.NoExpiration, 0),
	}
}

func (c *memRevCache) Get(_ context.Context, keys revcache.KeySet) (revcache.Revocations, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	revs := make(revcache.Revocations, len(keys))
	for k := range keys {
		if revInfo, ok := c.get(k.String()); ok {
			revs[k] = revInfo
		}
	}
	return revs, nil
}

func (c *memRevCache) GetAll(_ context.Context) (revcache.ResultChan, error) {
	// Since we have everything in memory anyway we just fill the channel at the start.
	c.lock.RLock()
	defer c.lock.RUnlock()
	items := c.c.Items()
	resCh := make(chan revcache.RevOrErr, len(items))
	for _, item := range items {
		if rev, ok := item.Object.(*path_mgmt.SignedRevInfo); ok {
			resCh <- revcache.RevOrErr{Rev: rev}
		}
	}
	close(resCh)
	return resCh, nil
}

func (c *memRevCache) get(key string) (*path_mgmt.SignedRevInfo, bool) {
	obj, ok := c.c.Get(key)
	if !ok {
		return nil, false
	}
	return obj.(*path_mgmt.SignedRevInfo), true
}

func (c *memRevCache) Insert(_ context.Context, rev *path_mgmt.SignedRevInfo) (bool, error) {
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

func (c *memRevCache) DeleteExpired(_ context.Context) (int64, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	var cnt int64
	c.c.OnEvicted(func(string, interface{}) {
		cnt++
	})
	c.c.DeleteExpired()
	return cnt, nil
}
