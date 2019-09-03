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
	"fmt"
	"sort"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
)

// SegWithHP is a segment with hidden path cfg ids.
type SegWithHP struct {
	Seg     *seg.Meta
	HPGroup hiddenpath.GroupId
}

func (s *SegWithHP) String() string {
	return fmt.Sprintf("{Seg: %v, HPGroup: %s}", s.Seg, s.HPGroup)
}

// Storage is used to store segments and revocations.
type Storage interface {
	StoreSegs(context.Context, []*SegWithHP) error
	StoreRevs(context.Context, []*path_mgmt.SignedRevInfo) error
}

// DefaultStorage wraps path DB and revocation cache and offers
// convenience methods that implement the Storage interface.
type DefaultStorage struct {
	PathDB   pathdb.PathDB
	RevCache revcache.RevCache
}

// StoreSegs stores the given segments in the pathdb in a transaction.
func (s *DefaultStorage) StoreSegs(ctx context.Context, segs []*SegWithHP) error {
	tx, err := s.PathDB.BeginTransaction(ctx, nil)
	if err != nil {
		return err
	}
	// Sort to prevent sql deadlock.
	sort.Slice(segs, func(i, j int) bool {
		return segs[i].Seg.Segment.GetLoggingID() < segs[j].Seg.Segment.GetLoggingID()
	})
	var insertedSegmentIDs []string
	defer tx.Rollback()
	for _, seg := range segs {
		n, err := tx.InsertWithHPCfgIDs(ctx, seg.Seg, convertHPGroupID(seg.HPGroup))
		if err != nil {
			return err
		} else if n > 0 {
			insertedSegmentIDs = append(insertedSegmentIDs, seg.Seg.Segment.GetLoggingID())
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if len(insertedSegmentIDs) > 0 {
		log.FromCtx(ctx).Debug("Segments inserted in DB", "segments", insertedSegmentIDs)
	}
	return nil
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
