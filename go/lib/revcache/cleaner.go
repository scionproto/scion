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

package revcache

import (
	"context"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
)

type cleaner struct {
	revCache RevCache
}

// NewCleaner creates a periodic.Task that deletes expired revocations from the given RevCache.
func NewCleaner(revCache RevCache) periodic.Task {
	return &cleaner{
		revCache: revCache,
	}
}

// Run implements periodic.Task.Run.
func (c *cleaner) Run(ctx context.Context) {
	count, err := c.revCache.DeleteExpired(ctx)
	if err != nil {
		log.Error("Failed to delete expired revocations", "err", err)
		return
	}
	if count > 0 {
		log.Info("Deleted expired revocations", "count", count)
	}
}
