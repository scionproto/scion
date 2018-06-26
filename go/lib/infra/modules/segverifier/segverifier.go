// Copyright 2018 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
)

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
func (u *Unit) Verify(ctx context.Context, unitResults chan UnitResult) {

	responses := make(chan ElemResult, u.Len())
	go verifySegment(ctx, u.SegMeta, []addr.ISD{}, responses)
	for index, sRevInfo := range u.SRevInfos {
		// FIXME(scrye): build actual trust trail here
		go verifyRevInfo(ctx, index, sRevInfo, []addr.ISD{}, responses)
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

type ElemResult struct {
	Index int
	Error error
}

func verifySegment(ctx context.Context, segment *seg.Meta, trail []addr.ISD, ch chan ElemResult) {

	for i, asEntry := range segment.Segment.ASEntries {
		// TODO(scrye): get valid chain, then verify ASEntry at index i with
		// the key from the chain
		_, _ = i, asEntry
	}
	select {
	case ch <- ElemResult{Index: -1, Error: nil}:
	default:
		panic("would block on channel")
	}
}

func verifyRevInfo(ctx context.Context, index int, signedRevInfo *path_mgmt.SignedRevInfo,
	trail []addr.ISD, ch chan ElemResult) {

	// TODO(scrye): get valid chain, then verify signedRevInfo.Blob with the
	// key from the chain
	select {
	case ch <- ElemResult{Index: index, Error: nil}:
	default:
		panic("would block on channel")
	}
}
