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
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
)

// Verifier is used to verify a segment reply.
type Verifier interface {
	Verify(context.Context, *path_mgmt.SegReply, net.Addr) (chan segverifier.UnitResult, int)
}

// SegVerifier is a convenience wrapper around segverifier that implements
// the Verifier interface.
type SegVerifier struct {
	Verifier infra.Verifier
}

// Verify calls segverifier for the given reply.
func (v *SegVerifier) Verify(ctx context.Context, reply *path_mgmt.SegReply,
	server net.Addr) (chan segverifier.UnitResult, int) {

	return segverifier.StartVerification(ctx, v.Verifier, server, reply.Recs.Recs,
		reply.Recs.SRevInfos)
}

// SegWithHP is a segment with hidden path cfg ids.
type SegWithHP struct {
	Seg      *seg.Meta
	HPCfgIds []*query.HPCfgID
}

func (s *SegWithHP) String() string {
	return fmt.Sprintf("{Seg: %v, HPCfgIds: %v}", s.Seg, s.HPCfgIds)
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
	var insertedSegmentIDs []string
	defer tx.Rollback()
	for _, seg := range segs {
		if n, err := tx.InsertWithHPCfgIDs(ctx, seg.Seg, seg.HPCfgIds); err != nil {
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

// ProcessedResult is the result of handling a segment reply.
type ProcessedResult struct {
	early      chan int
	full       chan struct{}
	err        error
	verifyErrs []error
}

// EarlyTriggerProcessed returns a channel that will contain the number of
// successfully stored segments once it is done processing the early trigger.
func (r *ProcessedResult) EarlyTriggerProcessed() <-chan int {
	return r.early
}

// FullReplyProcessed returns a channel that will be closed once the full reply
// has been processed.
func (r *ProcessedResult) FullReplyProcessed() <-chan struct{} {
	return r.full
}

// Err indicates the error that happened when storing the segments. This should
// only be accessed after FullReplyProcessed channel has been closed.
func (r *ProcessedResult) Err() error {
	return r.err
}

// VerificationErrors returns the list of verification errors that happened.
func (r *ProcessedResult) VerificationErrors() []error {
	return r.verifyErrs
}

// SegReplyHandler is a handler that verifies and stores seg replies. The
// handler supports an early trigger, so that a partial result can be stored
// early to possibly reply to clients earlier.
type SegReplyHandler struct {
	Verifier Verifier
	Storage  Storage
}

// Handle handles verifies and stores a single seg reply.
func (h *SegReplyHandler) Handle(ctx context.Context, reply *path_mgmt.SegReply, server net.Addr,
	earlyTrigger <-chan struct{}) *ProcessedResult {

	result := &ProcessedResult{
		early: make(chan int, 1),
		full:  make(chan struct{}),
	}
	verifiedCh, units := h.Verifier.Verify(ctx, reply, nil)
	if units == 0 {
		close(result.early)
		close(result.full)
		return result
	}

	go func() {
		defer log.LogPanicAndExit()
		h.verifyAndStore(ctx, earlyTrigger, result, verifiedCh, units)
	}()
	return result
}

func (h *SegReplyHandler) verifyAndStore(ctx context.Context,
	earlyTrigger <-chan struct{}, result *ProcessedResult,
	verifiedCh <-chan segverifier.UnitResult, units int) {

	verifiedUnits := make([]segverifier.UnitResult, 0, units)
	var allVerifyErrs []error
	totalSegsSaved := 0
	defer close(result.full)
	defer func() {
		if earlyTrigger != nil {
			// Unblock channel if done before triggered
			result.early <- totalSegsSaved
		}
	}()
	for u := 0; u < units; u++ {
		select {
		case verifiedUnit := <-verifiedCh:
			verifiedUnits = append(verifiedUnits, verifiedUnit)
		case <-earlyTrigger:
			// Reduce u since this does not process an additional unit.
			u--
			segs, verifyErrs, err := h.storeResults(ctx, verifiedUnits)
			allVerifyErrs = append(allVerifyErrs, verifyErrs...)
			totalSegsSaved += segs
			result.early <- segs
			// TODO(lukedirtwalker): log early store failure
			if err == nil {
				// clear already processed units
				verifiedUnits = verifiedUnits[:0]
			}
			// Make sure we do not select from this channel again
			earlyTrigger = nil
		}
	}
	segs, verifyErrs, err := h.storeResults(ctx, verifiedUnits)
	result.verifyErrs = append(allVerifyErrs, verifyErrs...)
	result.err = err
	totalSegsSaved += segs
}

func (h *SegReplyHandler) storeResults(ctx context.Context,
	verifiedUnits []segverifier.UnitResult) (int, []error, error) {

	var verifyErrs []error
	segs := make([]*SegWithHP, 0, len(verifiedUnits))
	var revs []*path_mgmt.SignedRevInfo
	for _, unit := range verifiedUnits {
		if err := unit.SegError(); err != nil {
			verifyErrs = append(verifyErrs, common.NewBasicError("Failed to verify seg", err,
				"seg", unit.Unit.SegMeta.Segment))
		} else {
			segs = append(segs, &SegWithHP{
				Seg:      unit.Unit.SegMeta,
				HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
			})
		}
		for idx, rev := range unit.Unit.SRevInfos {
			if err, ok := unit.Errors[idx]; ok {
				verifyErrs = append(verifyErrs, common.NewBasicError("Failed to verify rev", err,
					"rev", rev))
			} else {
				revs = append(revs, rev)
			}
		}
	}
	if len(segs) > 0 {
		if err := h.Storage.StoreSegs(ctx, segs); err != nil {
			return 0, verifyErrs, err
		}
	}
	if len(revs) > 0 {
		return len(segs), verifyErrs, h.Storage.StoreRevs(ctx, revs)
	}
	return len(segs), verifyErrs, nil
}
