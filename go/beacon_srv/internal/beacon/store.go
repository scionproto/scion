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
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

const maxResultChanSize = 32

type usager interface {
	Usage(beacon Beacon) Usage
}

// Store provides abstracted access to the beacon database in a non-core AS.
// The store helps inserting beacons and revocations, and selects the best beacons
// for given purposes based on the configured policies. It should not be used in a
// core AS.
type Store struct {
	baseStore
	policies Policies
}

// NewBeaconStore creates a new beacon store for a non-core AS.
func NewBeaconStore(policies Policies, db DB) (*Store, error) {
	policies.InitDefaults()
	if err := policies.Validate(); err != nil {
		return nil, err
	}
	s := &Store{
		baseStore: baseStore{
			db:   db,
			algo: baseAlgo{},
		},
		policies: policies,
	}
	s.baseStore.usager = &s.policies
	return s, nil
}

// BeaconsToPropagate returns a channel that provides all beacons to propagate
// at the time of the call. The selection is based on the configured propagation
// policy.
func (s *Store) BeaconsToPropagate(ctx context.Context) (<-chan BeaconOrErr, error) {
	return s.getBeacons(ctx, &s.policies.Prop)
}

// SegmentsToRegister returns a channel that provides all beacons to register at
// the time of the call. The selections is based on the configured policy for
// the requested segment type.
func (s *Store) SegmentsToRegister(ctx context.Context, segType proto.PathSegType) (
	<-chan BeaconOrErr, error) {

	switch {
	case segType == proto.PathSegType_down:
		return s.getBeacons(ctx, &s.policies.DownReg)
	case segType == proto.PathSegType_up:
		return s.getBeacons(ctx, &s.policies.UpReg)
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
		s.algo.SelectAndServe(beacons, results, policy.BestSetSize)
	}()
	return results, nil
}

// CoreStore provides abstracted access to the beacon database in a core AS. The
// store helps inserting beacons and revocations, and selects the best beacons
// for given purposes based on the configured policies. It should not be used in
// a non-core AS.
type CoreStore struct {
	baseStore
	policies CorePolicies
}

// NewCoreBeaconStore creates a new beacon store for a non-core AS.
func NewCoreBeaconStore(policies CorePolicies, db DB) (*CoreStore, error) {
	policies.InitDefaults()
	if err := policies.Validate(); err != nil {
		return nil, err
	}
	s := &CoreStore{
		baseStore: baseStore{
			db:   db,
			algo: baseAlgo{},
		},
		policies: policies,
	}
	s.usager = &s.policies
	return s, nil
}

// BeaconsToPropagate returns a channel that provides all beacons to propagate
// at the time of the call. The selection is based on the configured propagation
// policy.
func (s *CoreStore) BeaconsToPropagate(ctx context.Context) (<-chan BeaconOrErr, error) {
	return s.getBeacons(ctx, &s.policies.Prop)
}

// SegmentsToRegister returns a channel that provides all beacons to register at
// the time of the call. The selections is based on the configured policy for
// the requested segment type.
func (s *CoreStore) SegmentsToRegister(ctx context.Context, segType proto.PathSegType) (
	<-chan BeaconOrErr, error) {

	if segType != proto.PathSegType_core {
		return nil, common.NewBasicError("Unsupported segment type", nil, "type", segType)
	}
	return s.getBeacons(ctx, &s.policies.CoreReg)
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
			s.algo.SelectAndServe(beacons, results, policy.BestSetSize)
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
	db     DB
	usager usager
	algo   selectionAlgorithm
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
		usage := s.usager.Usage(beacon)
		if usage.None() {
			continue
		}
		if _, err := tx.InsertBeacon(ctx, beacon, usage); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InsertRevocations inserts the revocation into the BeaconDB. The provided
// revocation must be verified by the caller.
func (s *baseStore) InsertRevocations(ctx context.Context,
	revocations ...*path_mgmt.SignedRevInfo) error {

	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, sRev := range revocations {
		if err := tx.InsertRevocation(ctx, sRev); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteRevocation deletes the revocation from the BeaconDB.
func (s *baseStore) DeleteRevocation(ctx context.Context, ia addr.IA, ifid common.IFIDType) error {
	return s.db.DeleteRevocation(ctx, ia, ifid)
}

// DeleteExpiredBeacons deletes expired Beacons from the store.
func (s *baseStore) DeleteExpiredBeacons(ctx context.Context) (int, error) {
	return s.db.DeleteExpiredBeacons(ctx, time.Now())
}

// DeleteExpiredRevocations deletes expired Revocations from the store.
func (s *baseStore) DeleteExpiredRevocations(ctx context.Context) (int, error) {
	return s.db.DeleteExpiredRevocations(ctx, time.Now())
}

// DeleteRevokedBeacons deletes beacons containing revoked interfaces from the
// store.
func (s *baseStore) DeleteRevokedBeacons(ctx context.Context) (int, error) {
	return s.db.DeleteRevokedBeacons(ctx, time.Now())
}

// UpdatePolicy updates the policy. Beacons that are filtered by all
// policies after the update are removed.
func (s *baseStore) UpdatePolicy(ctx context.Context, policy Policy) error {
	return common.NewBasicError("policy update not supported", nil)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
