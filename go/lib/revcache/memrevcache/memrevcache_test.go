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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/revcachetest"
	"github.com/scionproto/scion/go/lib/xtest"
)

var _ (revcachetest.TestableRevCache) = (*testRevCache)(nil)

type testRevCache struct {
	*memRevCache
}

func (c *testRevCache) InsertExpired(t *testing.T, _ context.Context,
	rev *path_mgmt.SignedRevInfo) {

	newInfo, err := rev.RevInfo()
	xtest.FailOnErr(t, err)
	ttl := newInfo.Expiration().Sub(time.Now())
	if ttl >= 0 {
		panic("Should only be used for expired elements")
	}
	k := revcache.NewKey(newInfo.IA(), newInfo.IfID)
	key := k.String()
	c.c.Set(key, rev, time.Microsecond)
	// Unfortunately inserting with negative TTL makes entries available forever,
	// so we use 1 micro second and sleep afterwards
	// to simulate the insertion of an expired entry.
	time.Sleep(20 * time.Millisecond)
}

func TestRevCacheSuite(t *testing.T) {
	Convey("RevCache Suite", t, func() {
		revcachetest.TestRevCache(t,
			func() revcachetest.TestableRevCache {
				return &testRevCache{
					memRevCache: New(),
				}
			},
			func() {},
		)
	})
}
