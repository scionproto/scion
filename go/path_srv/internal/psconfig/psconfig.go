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

// Package psconfig contains the configuration of the path server.
package psconfig

import (
	"time"

	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	DefaultQueryInterval = 5 * time.Minute
)

type Config struct {
	// SegSync enables the "old" replication of down segments between cores,
	// using SegSync messages.
	SegSync  bool
	PathDB   pathstorage.PathDBConf
	RevCache pathstorage.RevCacheConf
	// QueryInterval specifies after how much time segments
	// for a destination should be refetched.
	QueryInterval util.DurWrap
}

func (c *Config) InitDefaults() {
	if c.QueryInterval.Duration == 0 {
		c.QueryInterval.Duration = DefaultQueryInterval
	}
	c.PathDB.InitDefaults()
	c.RevCache.InitDefaults()
}
