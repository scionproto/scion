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

package beacon

import (
	"context"
	"database/sql"
	"math"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

const maxResultChanSize = 32

// policies keeps track of all policies for a beacon store.
type policies struct {
	up   *Policy
	down *Policy
	core *Policy
	prop *Policy
}

// Usage returns the allowed usage of the beacon based on all available
// policies. For missing policies, the usage is not permitted.
func (p policies) Usage(beacon Beacon) Usage {
	var u Usage
	if p.up != nil && p.up.Filter.Apply(beacon) == nil {
		u |= UsageUpReg
	}
	if p.down != nil && p.down.Filter.Apply(beacon) == nil {
		u |= UsageDownReg
	}
	if p.core != nil && p.core.Filter.Apply(beacon) == nil {
		u |= UsageCoreReg
	}
	if p.prop != nil && p.prop.Filter.Apply(beacon) == nil {
		u |= UsageProp
	}
	return u
}

// Store provides abstracted access to the beacon database in a non-core AS.
// The store helps inserting beacons and revocations, and selects the best beacons
// for given purposes based on the configured policies. It should not be used in a
// core AS.
type Store struct {
	baseStore
}

// NewBeaconStore creates a new beacon store for a non-core AS.
func NewBeaconStore(prop, upReg, downReg Policy, db DB) *Store {
	prop.InitDefaults()
	upReg.InitDefaults()
	downReg.InitDefaults()
	s := &Store{
		baseStore: baseStore{
			db: db,
			policies: policies{
				prop: &prop,
				down: &downReg,
				up:   &upReg,
			},
		},
	}
	return s
}

// BeaconsToPropagate returns a channel that provides all beacons to propagate
// at the time of the call. The selection is based on the configured propagation
// policy.
func (s *Store) BeaconsToPropagate(ctx context.Context) (<-chan BeaconOrErr, error) {
	return s.getBeacons(ctx, s.policies.prop)
}

// SegmentsToRegister returns a channel that provides all beacons to register at
// the time of the call. The selections is based on the configured policy for
// the requested segment type.
func (s *Store) SegmentsToRegister(ctx context.Context, segType proto.PathSegType) (
	<-chan BeaconOrErr, error) {

	switch {
	case segType == proto.PathSegType_down:
		return s.getBeacons(ctx, s.policies.down)
	case segType == proto.PathSegType_up:
		return s.getBeacons(ctx, s.policies.up)
	default:
		return nil, common.NewBasicError("Unsupported segment type", nil, "type", segType)
	}
}

// getBeacons fetches the candidate beacons from the database and serves the
// best beacons according to the policy.
func (s *Store) getBeacons(ctx context.Context, policy *Policy) (<-chan BeaconOrErr, error) {
	beacons, err := s.db.CandidateBeacons(ctx, policy.CandidateSetSize,
		UsageFromPolicyType(policy.Type), addr.IA{})
	if err != nil {
		return nil, err
	}
	results := make(chan BeaconOrErr, min(maxResultChanSize, policy.BestSetSize))
	go func() {
		defer log.LogPanicAndExit()
		defer close(results)
		s.selectAndServe(beacons, results, policy)
	}()
	return results, nil
}

// CoreStore provides abstracted access to the beacon database in a core AS. The
// store helps inserting beacons and revocations, and selects the best beacons
// for given purposes based on the configured policies. It should not be used in
// a non-core AS.
type CoreStore struct {
	baseStore
}

// NewCoreBeaconStore creates a new beacon store for a non-core AS.
func NewCoreBeaconStore(prop, coreReg Policy, db DB) *CoreStore {
	prop.InitDefaults()
	coreReg.InitDefaults()
	s := &CoreStore{
		baseStore: baseStore{
			db: db,
			policies: policies{
				prop: &prop,
				core: &coreReg,
			},
		},
	}
	return s
}

// BeaconsToPropagate returns a channel that provides all beacons to propagate
// at the time of the call. The selection is based on the configured propagation
// policy.
func (s *CoreStore) BeaconsToPropagate(ctx context.Context) (<-chan BeaconOrErr, error) {
	return s.getBeacons(ctx, s.policies.prop)
}

// SegmentsToRegister returns a channel that provides all beacons to register at
// the time of the call. The selections is based on the configured policy for
// the requested segment type.
func (s *CoreStore) SegmentsToRegister(ctx context.Context, segType proto.PathSegType) (
	<-chan BeaconOrErr, error) {

	if segType != proto.PathSegType_core {
		return nil, common.NewBasicError("Unsupported segment type", nil, "type", segType)
	}
	return s.getBeacons(ctx, s.policies.core)
}

// getBeacons fetches the candidate beacons from the database and serves the
// best beacons according to the policy.
func (s *CoreStore) getBeacons(ctx context.Context, policy *Policy) (<-chan BeaconOrErr, error) {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Commit()
	srcs, err := tx.BeaconSources(ctx)
	if err != nil {
		return nil, err
	}
	results := make(chan BeaconOrErr, min(maxResultChanSize, len(srcs)*policy.BestSetSize))
	wg := sync.WaitGroup{}
	var errs []addr.IA
	for _, src := range srcs {
		beacons, err := tx.CandidateBeacons(ctx, policy.CandidateSetSize,
			UsageFromPolicyType(policy.Type), src)
		// Must not return, as the beacon channels have to be drained and a
		// partial result is better than no result at all.
		if err != nil {
			errs = append(errs, src)
			continue
		}
		wg.Add(1)
		go func() {
			defer log.LogPanicAndExit()
			defer wg.Done()
			s.selectAndServe(beacons, results, policy)
		}()
	}
	go func() {
		defer log.LogPanicAndExit()
		defer close(results)
		wg.Wait()
		if len(errs) > 0 {
			results <- BeaconOrErr{
				Err: common.NewBasicError("Unable to get beacons from db", nil, "srcs", errs),
			}
		}
	}()
	return results, nil
}

// baseStore is the basis for the beacon store.
type baseStore struct {
	db       DB
	policies policies
}

// InsertBeacons adds verified beacons to the store. Beacons that
// contain revoked interfaces are not added and do not cause an error.
func (s *baseStore) InsertBeacons(ctx context.Context, beacons ...Beacon) error {
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, beacon := range beacons {
		usage := s.policies.Usage(beacon)
		if usage.None() {
			continue
		}
		if _, err := tx.InsertBeacon(ctx, beacon, usage); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteExpiredBeacons deletes expired Beacons from the store.
func (s *baseStore) DeleteExpiredBeacons(ctx context.Context) (int, error) {
	return s.db.DeleteExpiredBeacons(ctx, time.Now())
}

// selectAndServe implements a very simple selection algorithm. The best beacon is
// the one with a shortest path. The second best is the most divers from the
// best beacon. The remaining k-2 beacons are filled with the remaining shortest
// beacons.
func (s *baseStore) selectAndServe(beacons <-chan BeaconOrErr, results chan<- BeaconOrErr,
	policy *Policy) {

	// The best beacon is the beacon with the shortest path. The result from the
	// database is sorted by path length.
	best, ok := s.serveShortestBeacons(beacons, results, policy)
	if !ok {
		return
	}
	// Select the most diverse compared to the best beacon from the remaining beacons.
	s.serveMostDiverse(best, beacons, results)
}

// serveShortsestBeacons serves the k-1 shortest beacons on the result channel.
func (s *baseStore) serveShortestBeacons(beacons <-chan BeaconOrErr, results chan<- BeaconOrErr,
	policy *Policy) (Beacon, bool) {

	var best Beacon
	i := 0
	for res := range beacons {
		if (best == Beacon{}) {
			best = res.Beacon
		}
		results <- res
		if res.Err != nil {
			return best, false
		}
		if i >= policy.BestSetSize-2 {
			break
		}
		i++
	}
	return best, true
}

// serveMostDiverse selects the most diverse beacon compared to the provided
// best beacon from all beacons that are in the channel and serves it in the
// result channel.
func (s *baseStore) serveMostDiverse(best Beacon, beacons <-chan BeaconOrErr,
	results chan<- BeaconOrErr) {

	maxDiversity := -1
	minLen := math.MaxUint16
	var diverse BeaconOrErr
	var err error
	for res := range beacons {
		if res.Err != nil {
			err = res.Err
			continue
		}
		diversity := best.Diversity(res.Beacon)
		l := len(res.Beacon.Segment.ASEntries)
		if diversity > maxDiversity || (diversity == maxDiversity && minLen > l) {
			diverse.Beacon, minLen, maxDiversity = res.Beacon, l, diversity
		}
	}
	if (diverse == BeaconOrErr{}) {
		if err != nil {
			results <- BeaconOrErr{Err: err}
		}
		return
	}
	results <- diverse
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
