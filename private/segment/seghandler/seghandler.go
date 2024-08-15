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

	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/segment/segverifier"
)

// Errors
var (
	ErrVerification = serrors.New("all segments failed to verify")
	ErrDB           = serrors.New("database error")
)

// Segments is a list of segments and revocations belonging to them.
// Optionally a hidden path group ID is attached.
type Segments struct {
	Segs []*seg.Meta
}

// Handler is a handler that verifies and stores seg replies. The handler
// supports an early trigger, so that a partial result can be stored early to
// possibly reply to clients earlier.
type Handler struct {
	Verifier Verifier
	Storage  Storage
}

// Handle verifies and stores a set of segments.
func (h *Handler) Handle(ctx context.Context, recs Segments, server net.Addr) *ProcessedResult {
	verifiedCh, units := h.Verifier.Verify(ctx, recs, server)
	if units == 0 {
		return &ProcessedResult{}
	}
	return h.verifyAndStore(ctx, verifiedCh, units)
}

func (h *Handler) verifyAndStore(ctx context.Context,
	verifiedCh <-chan segverifier.UnitResult, units int) *ProcessedResult {

	result := &ProcessedResult{}
	verifiedUnits := make([]segverifier.UnitResult, 0, units)
	for u := 0; u < units; u++ {
		verifiedUnits = append(verifiedUnits, <-verifiedCh)
	}
	verifyErrs, err := h.storeResults(ctx, verifiedUnits, &result.stats)
	result.verifyErrs = verifyErrs
	result.stats.verificationErrs(result.verifyErrs)
	switch {
	case err != nil:
		result.err = serrors.JoinNoStack(ErrDB, err)
	case result.stats.SegVerifyErrors() == units:
		result.err = serrors.JoinNoStack(ErrVerification, result.verifyErrs.ToError())
	}
	return result
}

func (h *Handler) storeResults(ctx context.Context, verifiedUnits []segverifier.UnitResult,
	stats *Stats) ([]error, error) {

	var verifyErrs []error
	segs := make([]*seg.Meta, 0, len(verifiedUnits))
	for _, unit := range verifiedUnits {
		if err := unit.SegError(); err != nil {
			verifyErrs = append(verifyErrs, err)
		} else {
			segs = append(segs, unit.Unit.SegMeta)
			stats.VerifiedSegs = append(stats.VerifiedSegs, unit.Unit.SegMeta)
		}
	}
	if len(segs) > 0 {
		storeSegStats, err := h.Storage.StoreSegs(ctx, segs)
		if err != nil {
			return verifyErrs, err
		}
		stats.addStoredSegs(storeSegStats)
	}
	return verifyErrs, nil
}
