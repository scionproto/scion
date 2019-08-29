// Copyright 2019 Anapaya Systems
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

package segfetcher

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

// NextQueryCleaner can be used to delete next query entries from a pathdb.
type NextQueryCleaner struct {
	PathDB pathdb.PathDB
}

// ResetQueryCache deletes all NextQuery entries for segments that contain the
// revoked interface.
func (c *NextQueryCleaner) ResetQueryCache(ctx context.Context, revInfo *path_mgmt.RevInfo) error {
	tx, err := c.PathDB.BeginTransaction(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	results, err := tx.Get(ctx, &query.Params{
		Intfs: []*query.IntfSpec{{IA: revInfo.IA(), IfID: revInfo.IfID}},
	})
	if err != nil {
		return err
	}
	if err := DeleteNextQueryEntries(ctx, tx, results); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteNextQueryEntries deletes all NextQuery entries that are described by
// the given query result set.
func DeleteNextQueryEntries(ctx context.Context, tx pathdb.Transaction,
	results query.Results) error {

	logger := log.FromCtx(ctx)
	nextQueriesToDelete := make(map[Request]struct{})
	for _, r := range results {
		var req Request
		switch r.Type {
		case proto.PathSegType_up:
			req = Request{Src: r.Seg.LastIA(), Dst: addr.IA{I: r.Seg.FirstIA().I}}
		case proto.PathSegType_core:
			req = Request{Src: r.Seg.LastIA(), Dst: r.Seg.FirstIA()}
		case proto.PathSegType_down:
			req = Request{Src: addr.IA{I: r.Seg.FirstIA().I}, Dst: r.Seg.LastIA()}
		default:
			logger.Error("Invalid seg type", "segType", r.Type)
			continue
		}
		nextQueriesToDelete[req] = struct{}{}
	}
	for nq := range nextQueriesToDelete {
		logger.Trace("Delete NQ", "src", nq.Src, "dst", nq.Dst)
		if _, err := tx.DeleteNQ(ctx, nq.Src, nq.Dst, nil); err != nil {
			return err
		}
	}
	return nil
}
