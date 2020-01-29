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
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Errors
var (
	ErrVerification = serrors.New("all segments failed to verify")
	ErrDB           = serrors.New("database error")
)

// Segments is a list of segments and revocations belonging to them.
// Optionally a hidden path group ID is attached.
type Segments struct {
	Segs      []*seg.Meta
	SRevInfos []*path_mgmt.SignedRevInfo
	HPGroupID hiddenpath.GroupId
}

// Handler is a handler that verifies and stores seg replies. The handler
// supports an early trigger, so that a partial result can be stored early to
// possibly reply to clients earlier.
type Handler struct {
	Verifier Verifier
	Storage  Storage
}

// Handle verifies and stores a set of segments.
func (h *Handler) Handle(ctx context.Context, recs Segments, server net.Addr,
	earlyTrigger <-chan struct{}) *ProcessedResult {

	result := &ProcessedResult{
		early: make(chan int, 1),
		full:  make(chan struct{}),
	}
	verifiedCh, units := h.Verifier.Verify(ctx, recs, server)
	if units == 0 {
		close(result.early)
		close(result.full)
		return result
	}

	go func() {
		defer log.HandlePanic()
		h.verifyAndStore(ctx, earlyTrigger, result, verifiedCh,
			units, recs.HPGroupID)
	}()
	return result
}

func (h *Handler) verifyAndStore(ctx context.Context,
	earlyTrigger <-chan struct{}, result *ProcessedResult,
	verifiedCh <-chan segverifier.UnitResult,
	units int, hpGroupID hiddenpath.GroupId) {

	verifiedUnits := make([]segverifier.UnitResult, 0, units)
	var allVerifyErrs serrors.List
	defer close(result.full)
	defer func() {
		if earlyTrigger != nil {
			// Unblock channel if done before triggered
			result.early <- result.stats.segDB.Total()
		}
	}()
	for u := 0; u < units; u++ {
		select {
		case verifiedUnit := <-verifiedCh:
			verifiedUnits = append(verifiedUnits, verifiedUnit)
		case <-earlyTrigger:
			// Reduce u since this does not process an additional unit.
			u--
			verifyErrs, err := h.storeResults(ctx, verifiedUnits, hpGroupID, &result.stats)
			allVerifyErrs = append(allVerifyErrs, verifyErrs...)
			result.early <- result.stats.segDB.Total()
			if err == nil {
				// clear already processed units
				verifiedUnits = verifiedUnits[:0]
			} else {
				// reset stats
				result.stats = Stats{}
				log.FromCtx(ctx).Warn("Storing on early trigger failed, continue processing",
					"err", err)
			}
			// Make sure we do not select from this channel again
			earlyTrigger = nil
		}
	}
	verifyErrs, err := h.storeResults(ctx, verifiedUnits, hpGroupID, &result.stats)
	result.verifyErrs = append(allVerifyErrs, verifyErrs...)
	result.stats.verificationErrs(result.verifyErrs)
	switch {
	case err != nil:
		result.err = serrors.Wrap(ErrDB, err)
	case result.stats.SegVerifyErrors() == units:
		result.err = serrors.Wrap(ErrVerification, result.verifyErrs.ToError())
	}
}

func (h *Handler) storeResults(ctx context.Context, verifiedUnits []segverifier.UnitResult,
	hpGroupID hiddenpath.GroupId, stats *Stats) ([]error, error) {

	var verifyErrs []error
	segs := make([]*SegWithHP, 0, len(verifiedUnits))
	var revs []*path_mgmt.SignedRevInfo
	for _, unit := range verifiedUnits {
		if err := unit.SegError(); err != nil {
			verifyErrs = append(verifyErrs, err)
		} else {
			segs = append(segs, &SegWithHP{
				Seg:     unit.Unit.SegMeta,
				HPGroup: hpGroupID,
			})
			stats.VerifiedSegs = append(stats.VerifiedSegs, &SegWithHP{
				Seg:     unit.Unit.SegMeta,
				HPGroup: hpGroupID,
			})
		}
		for idx, rev := range unit.Unit.SRevInfos {
			if err, ok := unit.Errors[idx]; ok {
				verifyErrs = append(verifyErrs, err)
			} else {
				revs = append(revs, rev)
				stats.VerifiedRevs = append(stats.VerifiedRevs, rev)
			}
		}
	}
	if len(segs) > 0 {
		storeSegStats, err := h.Storage.StoreSegs(ctx, segs)
		if err != nil {
			return verifyErrs, err
		}
		stats.addStoredSegs(storeSegStats)
	}
	if len(revs) > 0 {
		if err := h.Storage.StoreRevs(ctx, revs); err != nil {
			return verifyErrs, err
		}
		stats.StoredRevs = append(stats.StoredRevs, revs...)
	}
	return verifyErrs, nil
}

func convertHPGroupID(id hiddenpath.GroupId) []*query.HPCfgID {
	return []*query.HPCfgID{
		{
			IA: addr.IA{
				A: id.OwnerAS,
			},
			ID: uint64(id.Suffix),
		},
	}
}
