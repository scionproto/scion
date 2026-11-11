// Copyright 2026 ETH Zurich
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

package segreq

import (
	"time"

	cache "zgo.at/zcache/v2"

	"github.com/scionproto/scion/pkg/addr"
	seg "github.com/scionproto/scion/pkg/segment"
)

type Key struct {
	Src addr.IA
	Dst addr.IA
}

type Store struct {
	c *cache.Cache[Key, []CombinedPath]
}

type CombinedPath struct {
	UpSegment   *seg.PathSegment
	CoreSegment *seg.PathSegment
	DownSegment *seg.PathSegment
}

func (c *CombinedPath) Length() int {
	l := 0
	if c.UpSegment != nil {
		l += len(c.UpSegment.ASEntries)
	}
	if c.CoreSegment != nil {
		l += len(c.CoreSegment.ASEntries)
	}
	if c.DownSegment != nil {
		l += len(c.DownSegment.ASEntries)
	}
	return l
}

func NewStore() *Store {
	return &Store{
		c: cache.New[Key, []CombinedPath](time.Minute, time.Minute),
	}
}

func (s *Store) Set(src addr.IA, dst addr.IA, path []CombinedPath) {
	s.c.Set(Key{Src: src, Dst: dst}, path)
}

func (s *Store) Get(src addr.IA, dst addr.IA) ([]CombinedPath, bool) {
	return s.c.Get(Key{Src: src, Dst: dst})
}
