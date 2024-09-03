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

	cache "zgo.at/zcache/v2"

	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/private/revcache"
)

var _ revcache.RevCache = (*memRevCache)(nil)

type memRevCache struct {
	// Do not embed or use type directly to reduce the cache's API surface
	c    *cache.Cache[revcache.Key, *path_mgmt.RevInfo]
	lock sync.RWMutex
}

// New creates a new RevCache, backed by an in memory cache.
func New() *memRevCache {
	return &memRevCache{
		// We insert all the items with expiration so no need to have a default expiration.
		// The cleaning should happen manually using the DeleteExpired method.
		c: cache.New[revcache.Key, *path_mgmt.RevInfo](cache.NoExpiration, 0),
	}
}

func (c *memRevCache) Get(_ context.Context, key revcache.Key) (*path_mgmt.RevInfo, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if revInfo, ok := c.c.Get(key); ok {
		return revInfo, nil
	}
	return nil, nil
}

func (c *memRevCache) GetAll(_ context.Context) (revcache.ResultChan, error) {
	// Since we have everything in memory anyway we just fill the channel at the start.
	c.lock.RLock()
	defer c.lock.RUnlock()
	items := c.c.Items()
	resCh := make(chan revcache.RevOrErr, len(items))
	for _, item := range items {
		resCh <- revcache.RevOrErr{Rev: item.Object}
	}
	close(resCh)
	return resCh, nil
}

func (c *memRevCache) Insert(_ context.Context, rev *path_mgmt.RevInfo) (bool, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	ttl := time.Until(rev.Expiration())
	if ttl <= 0 {
		return false, nil
	}
	key := revcache.NewKey(rev.IA(), rev.IfID)
	val, ok := c.c.Get(key)
	if !ok {
		c.c.SetWithExpire(key, rev, ttl)
		return true, nil
	}
	if rev.Timestamp().After(val.Timestamp()) {
		c.c.SetWithExpire(key, rev, ttl)
		return true, nil
	}
	return false, nil
}

func (c *memRevCache) DeleteExpired(_ context.Context) (int64, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	var cnt int64
	c.c.OnEvicted(func(revcache.Key, *path_mgmt.RevInfo) {
		cnt++
	})
	c.c.DeleteExpired()
	return cnt, nil
}

func (c *memRevCache) Close() error { return nil }

func (c *memRevCache) SetMaxOpenConns(_ int) {}

func (c *memRevCache) SetMaxIdleConns(_ int) {}
