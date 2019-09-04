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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/query"
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
		defer log.LogPanicAndExit()
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
	var allVerifyErrs []error
	totalSegsSaved := 0
	var allRevs []*path_mgmt.SignedRevInfo
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
			segs, revs, verifyErrs, err := h.storeResults(ctx, verifiedUnits, hpGroupID)
			allVerifyErrs = append(allVerifyErrs, verifyErrs...)
			totalSegsSaved += segs
			allRevs = append(allRevs, revs...)
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
	segs, revs, verifyErrs, err := h.storeResults(ctx, verifiedUnits, hpGroupID)
	result.verifyErrs = append(allVerifyErrs, verifyErrs...)
	result.err = err
	totalSegsSaved += segs
	result.segs = totalSegsSaved
	result.revs = append(allRevs, revs...)
}

func (h *Handler) storeResults(ctx context.Context, verifiedUnits []segverifier.UnitResult,
	hpGroupID hiddenpath.GroupId) (int, []*path_mgmt.SignedRevInfo, []error, error) {

	var verifyErrs []error
	segs := make([]*SegWithHP, 0, len(verifiedUnits))
	var revs []*path_mgmt.SignedRevInfo
	for _, unit := range verifiedUnits {
		if err := unit.SegError(); err != nil {
			verifyErrs = append(verifyErrs, common.NewBasicError("Failed to verify seg", err,
				"seg", unit.Unit.SegMeta.Segment))
		} else {
			segs = append(segs, &SegWithHP{
				Seg:     unit.Unit.SegMeta,
				HPGroup: hpGroupID,
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
			return 0, nil, verifyErrs, err
		}
	}
	if len(revs) > 0 {
		if err := h.Storage.StoreRevs(ctx, revs); err != nil {
			return len(segs), nil, verifyErrs, h.Storage.StoreRevs(ctx, revs)
		}
	}
	return len(segs), revs, verifyErrs, nil
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
