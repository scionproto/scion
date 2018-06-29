// Copyright 2018 ETH Zurich
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
	"fmt"
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
)

type RevCache struct {
	// Do not embed or use type directly to reduce the cache's API surface
	c *cache.Cache
}

func NewRevCache(defaultExpiration, cleanupInterval time.Duration) *RevCache {
	return &RevCache{
		c: cache.New(defaultExpiration, cleanupInterval),
	}
}

func (c *RevCache) Get(ia addr.IA, ifid common.IFIDType) (*path_mgmt.SignedRevInfo, bool) {
	obj, ok := c.c.Get(revCacheKey(ia, ifid))
	if !ok {
		return nil, false
	}
	return obj.(*path_mgmt.SignedRevInfo), true
}

func (c *RevCache) Add(ia addr.IA, ifid common.IFIDType, rev *path_mgmt.SignedRevInfo,
	ttl time.Duration) {

	c.c.Add(revCacheKey(ia, ifid), rev, ttl)
}

func revCacheKey(ia addr.IA, ifid common.IFIDType) string {
	return fmt.Sprintf("%s#%s", ia, ifid)
}
