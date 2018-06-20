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

package verifysegs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
)

// BuildVerificationUnits constructs one verification unit for each segment,
// together with its associated revocations.
func BuildVerificationUnits(segMetas []*seg.Meta,
	sRevInfos []*path_mgmt.SignedRevInfo) []*VerificationUnit {

	var units []*VerificationUnit
	for _, segMeta := range segMetas {
		unit := &VerificationUnit{SegMeta: segMeta}
		for _, sRevInfo := range sRevInfos {
			revInfo, err := sRevInfo.RevInfo()
			if err != nil {
				panic(err)
			}
			if metaContainsInterface(segMeta, revInfo.IA(), common.IFIDType(revInfo.IfID)) {
				unit.SRevInfos = append(unit.SRevInfos, sRevInfo)
			}
		}
		units = append(units, unit)
	}
	return units
}

func metaContainsInterface(segMeta *seg.Meta, ia addr.IA, ifid common.IFIDType) bool {
	for _, asEntry := range segMeta.Segment.ASEntries {
		for _, entry := range asEntry.HopEntries {
			hf, err := entry.HopField()
			if err != nil {
				panic(err)
			}
			if asEntry.IA().Eq(ia) && (hf.ConsEgress == ifid || hf.ConsIngress == ifid) {
				return true
			}
		}
	}
	return false
}

// VerifyUnit verifies a single unit, putting the results of verifications on
// unitResults.
func VerifyUnit(ctx context.Context, unit *VerificationUnit,
	unitResults chan UnitVerificationResult) {

	subCtx, subCtxCancelF := context.WithCancel(ctx)
	// We return when either (1) ctx is done, (2) all verification succeeds,
	// (3) any verification fails. In all these cases, it's ok to immediately
	// cancel all workers.
	defer subCtxCancelF()
	// Build trail here because we need to pass it into VerifyRevInfo as it
	// doesn't have enough topology information to build it
	var trail []addr.ISD
	for _, asEntry := range unit.SegMeta.Segment.ASEntries {
		trail = append(trail, asEntry.IA().I)
	}
	responses := make(chan VerificationResult, unit.Len())
	go verifySegment(subCtx, unit.SegMeta, trail, responses)
	for index, sRevInfo := range unit.SRevInfos {
		subtrail := getTrailSlice(sRevInfo, trail)
		go verifyRevInfo(subCtx, index, sRevInfo, subtrail, responses)
	}
	// Response writers must guarantee that the for returns before (or very
	// close around) ctx.Done()
	errs := make(map[int]error)
	for numResults := 0; numResults < unit.Len(); numResults++ {
		result := <-responses
		if result.Error != nil {
			errs[result.Index] = result.Error
		}
	}
	select {
	case unitResults <- UnitVerificationResult{Unit: unit, Errors: errs}:
	default:
		panic("would block on channel")
	}
}

func verifySegment(ctx context.Context, segment *seg.Meta, trail []addr.ISD,
	ch chan VerificationResult) {

	for i, asEntry := range segment.Segment.ASEntries {
		// TODO(scrye): get valid chain, then verify ASEntry at index i with
		// the key from the chain
		_, _ = i, asEntry
	}
	select {
	case ch <- VerificationResult{Index: -1, Error: nil}:
	default:
		panic("would block on channel")
	}
}

func verifyRevInfo(ctx context.Context, index int, signedRevInfo *path_mgmt.SignedRevInfo,
	trail []addr.ISD, ch chan VerificationResult) {

	// TODO(scrye): get valid chain, then verify signedRevInfo.Blob with the
	// key from the chain
	select {
	case ch <- VerificationResult{Index: index, Error: nil}:
	default:
		panic("would block on channel")
	}
}

func getTrailSlice(sRevInfo *path_mgmt.SignedRevInfo, trail []addr.ISD) []addr.ISD {
	info, err := sRevInfo.RevInfo()
	if err != nil {
		// Should be caught in first pass
		panic(err)
	}

	isd := info.IA().I
	for i := range trail {
		if trail[i] == isd {
			return trail[:i+1]
		}
	}
	// should never happen, the ISD in the revinfo has already been matched
	// when the verification unit was constructed
	panic(fmt.Sprintf("isd %d not in trail %v", isd, trail))
}

type VerificationResult struct {
	Index int
	Error error
}

type UnitVerificationResult struct {
	Unit   *VerificationUnit
	Errors map[int]error
}

// VerificationUnit contains multiple verification items.
type VerificationUnit struct {
	SegMeta   *seg.Meta
	SRevInfos []*path_mgmt.SignedRevInfo
}

func (unit *VerificationUnit) Len() int {
	return len(unit.SRevInfos) + 1
}

// Trigger represents a timer with delayed arming. Once Arm is called, the
// object's Done() method will return after d time. If d is 0, Done will
// instead block forever.
type Trigger struct {
	d    time.Duration
	ch   chan struct{}
	once sync.Once
}

func NewTrigger(d time.Duration) *Trigger {
	return &Trigger{
		d:  d,
		ch: make(chan struct{}, 0),
	}
}

func (t *Trigger) Done() <-chan struct{} {
	return t.ch
}

// Arm starts the trigger's preset timer, and returns the corresponding timer
// object. If the trigger is not configured with a timer, nil is returned.
func (t *Trigger) Arm() *time.Timer {
	var timer *time.Timer
	t.once.Do(
		func() {
			if t.d != 0 {
				timer = time.AfterFunc(t.d, func() { close(t.ch) })
			}
		},
	)
	return timer
}

func (t *Trigger) Triggered() bool {
	select {
	case <-t.ch:
		return true
	default:
		return false
	}
}
