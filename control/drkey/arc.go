// Copyright 2022 ETH Zurich
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

package drkey

import (
	"github.com/hashicorp/golang-lru/arc/v2"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// Level1ARC maintains an Adaptative Replacement Cache, storing
// the necessary metadata to prefetch Level1 keys.
type Level1ARC struct {
	cache *arc.ARCCache[Level1PrefetchInfo, struct{}]
}

// NewLevel1ARC returns a Level1ARC cache of a given size.
func NewLevel1ARC(size int) (*Level1ARC, error) {
	cache, err := arc.NewARC[Level1PrefetchInfo, struct{}](size)
	if err != nil {
		return nil, serrors.Wrap("creating Level1ARC cache", err)
	}
	return &Level1ARC{
		cache: cache,
	}, nil
}

// Update is intended to merely update the frequency of a given Level1Key
// in the ARC cache.
func (c *Level1ARC) Update(keyPair Level1PrefetchInfo) {
	c.cache.Add(keyPair, struct{}{})
}

// Info returns the list of AS currently in cache.
func (c *Level1ARC) Info() []Level1PrefetchInfo {
	list := []Level1PrefetchInfo{}
	for _, k := range c.cache.Keys() {
		lvl1Info := k
		list = append(list, lvl1Info)
	}
	return list
}
