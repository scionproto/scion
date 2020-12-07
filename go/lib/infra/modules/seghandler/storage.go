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

package seghandler

import (
	"context"
	"sort"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
)

// SegStats provides statistics about segment insertion/updates.
type SegStats struct {
	// InsertedSegs are the log IDs of the inserted segments.
	InsertedSegs []string
	// UpdatedSegs are the log IDs of the updated segments.
	UpdatedSegs []string
}

// Total returns the total amount of updates and inserts.
func (s SegStats) Total() int {
	return len(s.InsertedSegs) + len(s.UpdatedSegs)
}

// Log logs the statistics with the given logger.
func (s *SegStats) Log(logger log.Logger) {
	if len(s.InsertedSegs) > 0 {
		logger.Debug("Segments inserted in DB", "segments", s.InsertedSegs)
	}
	if len(s.UpdatedSegs) > 0 {
		logger.Debug("Segments updated in DB", "segments", s.UpdatedSegs)
	}
}

// Storage is used to store segments and revocations.
type Storage interface {
	StoreSegs(context.Context, []*seg.Meta) (SegStats, error)
	StoreRevs(context.Context, []*path_mgmt.SignedRevInfo) error
}

// DefaultStorage wraps path DB and revocation cache and offers
// convenience methods that implement the Storage interface.
type DefaultStorage struct {
	PathDB   pathdb.PathDB
	RevCache revcache.RevCache
}

// StoreSegs stores the given segments in the pathdb in a transaction.
func (s *DefaultStorage) StoreSegs(ctx context.Context, segs []*seg.Meta) (SegStats, error) {
	tx, err := s.PathDB.BeginTransaction(ctx, nil)
	if err != nil {
		return SegStats{}, err
	}
	defer tx.Rollback()
	// Sort to prevent sql deadlock.
	sort.Slice(segs, func(i, j int) bool {
		return segs[i].Segment.GetLoggingID() < segs[j].Segment.GetLoggingID()
	})
	segStats := SegStats{}
	for _, seg := range segs {
		stats, err := tx.Insert(ctx, seg)
		if err != nil {
			return SegStats{}, err
		}
		if stats.Inserted > 0 {
			segStats.InsertedSegs = append(segStats.InsertedSegs, seg.Segment.GetLoggingID())
		} else if stats.Updated > 0 {
			segStats.UpdatedSegs = append(segStats.UpdatedSegs, seg.Segment.GetLoggingID())
		}
	}
	if err := tx.Commit(); err != nil {
		return SegStats{}, err
	}
	segStats.Log(log.FromCtx(ctx))
	return segStats, nil
}

// StoreRevs stores the given revocations in the revocation cache.
func (s *DefaultStorage) StoreRevs(ctx context.Context,
	revs []*path_mgmt.SignedRevInfo) error {

	for _, rev := range revs {
		if _, err := s.RevCache.Insert(ctx, rev); err != nil {
			return err
		}
	}
	return nil
}
