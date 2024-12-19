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

package memrevcache

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/revcache/revcachetest"
)

var _ (revcachetest.TestableRevCache) = (*testRevCache)(nil)

type testRevCache struct {
	*memRevCache
}

func (c *testRevCache) InsertExpired(t *testing.T, _ context.Context,
	rev *path_mgmt.RevInfo) {

	ttl := time.Until(rev.Expiration())
	if ttl >= 0 {
		panic("Should only be used for expired elements")
	}
	key := revcache.NewKey(rev.IA(), rev.IfID)
	c.c.SetWithExpire(key, rev, time.Microsecond)
	// Unfortunately inserting with negative TTL makes entries available forever,
	// so we use 1 micro second and sleep afterwards
	// to simulate the insertion of an expired entry.
	time.Sleep(20 * time.Millisecond)
}

func (c *testRevCache) Prepare(t *testing.T, _ context.Context) {
	// For this backend the easiest is to create a new backend.
	c.memRevCache = New()
}

func TestRevCacheSuite(t *testing.T) {
	revcachetest.TestRevCache(t, &testRevCache{memRevCache: New()})
}
