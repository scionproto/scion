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

// Package segverifier implements primitives for verifying path segments.
//
// A Unit contains a path segment, and all the revocations that reference IFIDs
// in that path segment.
//
// When a unit is verified, it spawns one goroutine for the path segment's
// verification, and one goroutine for the verification of each revocation. It
// then collects the results from all workers (forcefully terminating them if
// the unit's context is Done). A UnitResult object is returned, containing a
// reference to the Unit itself and a map of errors. The map only contains
// non-nil errors as values, and the keys are represented by the following:
//   - If the path segment verification failed, its error is contained at key -1
//   - If a revocation verification failed, its error is contained at key x,
//   where x is the position of the revocation in the slice of SignedRevInfos
//   passed to BuildVerificationUnits.
package segverifier

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
)

const (
	segErrIndex = -1
)

// SegVerified is the callback for a successful segment verification.
// The function must adhere to the given context.
type SegVerified func(context.Context, *seg.Meta)

// SegVerificationFailed is the callback for a failed segment verification.
// The function must return immediately.
type SegVerificationFailed func(*seg.Meta, error)

// RevVerified is the callback for a successful revocation verification.
// The function must adhere to the given context.
type RevVerified func(context.Context, *path_mgmt.SignedRevInfo)

// RevVerificationFailed is the callback for a failed revocation verification.
// The function must return immediately.
type RevVerificationFailed func(*path_mgmt.SignedRevInfo, error)

// Verify starts the verification for the given segMeta and sRevInfos.
// The verifiedSeg and verifiedRev callbacks are called for verified segs/revs.
// The segError/revError callbacks are called for verification errors.
func Verify(ctx context.Context, store infra.TrustStore, server net.Addr, segMetas []*seg.Meta,
	sRevInfos []*path_mgmt.SignedRevInfo, verifiedSeg SegVerified, verifiedRev RevVerified,
	segError SegVerificationFailed, revError RevVerificationFailed) {

	unitResultsC, units := StartVerification(ctx, store, server, segMetas, sRevInfos)
Loop:
	for numResults := 0; numResults < units; numResults++ {
		select {
		case result := <-unitResultsC:
			if err := result.SegError(); err != nil {
				segError(result.Unit.SegMeta, err)
			} else {
				verifiedSeg(ctx, result.Unit.SegMeta)
			}
			// Insert successfully verified revocations into the revcache
			for index, revocation := range result.Unit.SRevInfos {
				if err, ok := result.Errors[index]; ok {
					revError(revocation, err)
				} else {
					verifiedRev(ctx, revocation)
				}
			}
		case <-ctx.Done():
			break Loop
		}
	}
}

// StartVerification builds the units for the given segMetas and sRevInfos
// and spawns verify method on the units.
// StartVerification returns a channel for the UnitResult and the expected amount of results.
func StartVerification(ctx context.Context, store infra.TrustStore, server net.Addr,
	segMetas []*seg.Meta, sRevInfos []*path_mgmt.SignedRevInfo) (chan UnitResult, int) {

	units := BuildUnits(segMetas, sRevInfos)
	unitResultsC := make(chan UnitResult, len(units))
	for _, unit := range units {
		go unit.Verify(ctx, store, server, unitResultsC)
	}
	return unitResultsC, len(units)
}

// Unit contains multiple verification items.
type Unit struct {
	SegMeta   *seg.Meta
	SRevInfos []*path_mgmt.SignedRevInfo
}

// BuildUnits constructs one verification unit for each segment,
// together with its associated revocations.
func BuildUnits(segMetas []*seg.Meta,
	sRevInfos []*path_mgmt.SignedRevInfo) []*Unit {

	var units []*Unit
	for _, segMeta := range segMetas {
		unit := &Unit{SegMeta: segMeta}
		for _, sRevInfo := range sRevInfos {
			revInfo, err := sRevInfo.RevInfo()
			if err != nil {
				panic(err)
			}
			if segMeta.Segment.ContainsInterface(revInfo.IA(), common.IFIDType(revInfo.IfID)) {
				unit.SRevInfos = append(unit.SRevInfos, sRevInfo)
			}
		}
		units = append(units, unit)
	}
	return units
}

func (u *Unit) Len() int {
	return len(u.SRevInfos) + 1
}

// Verify verifies a single unit, putting the results of verifications on
// unitResults.
func (u *Unit) Verify(ctx context.Context, store infra.TrustStore,
	server net.Addr, unitResults chan UnitResult) {

	responses := make(chan ElemResult, u.Len())
	go verifySegment(ctx, store, server, u.SegMeta, responses)
	for index, sRevInfo := range u.SRevInfos {
		go verifyRevInfo(ctx, store, server, index, sRevInfo, responses)
	}
	// Response writers must guarantee that the for loop below returns before
	// (or very close around) ctx.Done()
	errs := make(map[int]error)
	for numResults := 0; numResults < u.Len(); numResults++ {
		result := <-responses
		if result.Error != nil {
			errs[result.Index] = result.Error
		}
	}
	select {
	case unitResults <- UnitResult{Unit: u, Errors: errs}:
	default:
		panic("would block on channel")
	}
}

type UnitResult struct {
	Unit   *Unit
	Errors map[int]error
}

// SegError returns the verification error of the segment or nil if there was none.
func (r *UnitResult) SegError() error {
	if err, ok := r.Errors[segErrIndex]; ok {
		return err
	}
	return nil
}

type ElemResult struct {
	Index int
	Error error
}

func verifySegment(ctx context.Context, store infra.TrustStore, server net.Addr, segment *seg.Meta,
	ch chan ElemResult) {

	err := VerifySegment(ctx, store, server, segment)
	select {
	case ch <- ElemResult{Index: segErrIndex, Error: err}:
	default:
		panic("would block on channel")
	}
}

func VerifySegment(ctx context.Context, store infra.TrustStore, server net.Addr,
	segment *seg.Meta) error {

	for i, asEntry := range segment.Segment.ASEntries {
		chain, err := store.GetValidChain(ctx, asEntry.IA(), server)
		if err != nil {
			return err
		}
		err = segment.Segment.VerifyASEntry(chain.Leaf.SubjectSignKey, i)
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyRevInfo(ctx context.Context, store infra.TrustStore, server net.Addr, index int,
	signedRevInfo *path_mgmt.SignedRevInfo, ch chan ElemResult) {

	err := VerifyRevInfo(ctx, store, server, signedRevInfo)
	select {
	case ch <- ElemResult{Index: index, Error: err}:
	default:
		panic("would block on channel")
	}
}

func VerifyRevInfo(ctx context.Context, store infra.TrustStore, server net.Addr,
	signedRevInfo *path_mgmt.SignedRevInfo) error {

	revInfo, err := signedRevInfo.RevInfo()
	if err != nil {
		return err
	}
	chain, err := store.GetValidChain(ctx, revInfo.IA(), server)
	if err != nil {
		return err
	}
	return signedRevInfo.Sign.Verify(chain.Leaf.SubjectSignKey, signedRevInfo.Blob)
}
