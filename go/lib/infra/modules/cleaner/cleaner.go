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

package cleaner

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/periodic"
)

var _ periodic.Task = (*Cleaner)(nil)

type Cleaner struct {
	pathDB pathdb.PathDB
}

// New creates a new Cleaner Task for the given pathDB.
func New(pathDB pathdb.PathDB) *Cleaner {
	cleaner := &Cleaner{
		pathDB: pathDB,
	}
	return cleaner
}

func (c *Cleaner) Run(ctx context.Context) {
	count, err := c.pathDB.DeleteExpired(ctx, time.Now())
	if err != nil {
		log.Error("Failed to delete expired segments", "err", err)
		return
	}
	log.Info("Deleted expired segments", "count", count)
}
