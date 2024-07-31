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

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
)

type usager interface {
	Filter(beacon Beacon) error
	Usage(beacon Beacon) Usage
}

type storeOptions struct {
	chainChecker ChainProvider
}

type StoreOption interface {
	apply(o *storeOptions)
}

type chainCheckerOption struct{ ChainProvider }

func (c chainCheckerOption) apply(o *storeOptions) {
	o.chainChecker = c.ChainProvider
}

// WithCheckChain ensures that only beacons for which all the required
// certificate chains are available are returned. This can be paired with a
// chain provider that only returns locally available chains to ensure that
// beacons are verifiable with cryptographic material available in the local
// trust store.
func WithCheckChain(p ChainProvider) StoreOption {
	return chainCheckerOption{p}
}

func applyStoreOptions(opts []StoreOption) storeOptions {
	var o storeOptions
	for _, f := range opts {
		f.apply(&o)
	}
	return o
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
func NewBeaconStore(policies Policies, db DB, opts ...StoreOption) (*Store, error) {
	policies.InitDefaults()
	if err := policies.Validate(); err != nil {
		return nil, err
	}
	o := applyStoreOptions(opts)
	s := &Store{
		baseStore: baseStore{
			db:   db,
			algo: selectAlgo(o),
		},
		policies: policies,
	}
	s.baseStore.usager = &s.policies
	return s, nil
}

// BeaconsToPropagate returns a slice  all beacons to propagate at the time of the call.
// The selection is based on the configured propagation policy.
func (s *Store) BeaconsToPropagate(ctx context.Context) ([]Beacon, error) {
	return s.getBeacons(ctx, &s.policies.Prop)
}

// SegmentsToRegister returns a channel that provides all beacons to register at
// the time of the call. The selections is based on the configured policy for
// the requested segment type.
func (s *Store) SegmentsToRegister(ctx context.Context, segType seg.Type) ([]Beacon, error) {
	switch segType {
	case seg.TypeDown:
		return s.getBeacons(ctx, &s.policies.DownReg)
	case seg.TypeUp:
		return s.getBeacons(ctx, &s.policies.UpReg)
	default:
		return nil, serrors.New("Unsupported segment type", "type", segType)
	}
}

// getBeacons fetches the candidate beacons from the database and serves the
// best beacons according to the policy.
func (s *Store) getBeacons(ctx context.Context, policy *Policy) ([]Beacon, error) {
	beacons, err := s.db.CandidateBeacons(ctx, policy.CandidateSetSize,
		UsageFromPolicyType(policy.Type), 0)
	if err != nil {
		return nil, err
	}
	return s.algo.SelectBeacons(ctx, beacons, policy.BestSetSize), nil
}

// MaxExpTime returns the segment maximum expiration time for the given policy.
func (s *Store) MaxExpTime(policyType PolicyType) uint8 {
	switch policyType {
	case UpRegPolicy:
		return *s.policies.UpReg.MaxExpTime
	case DownRegPolicy:
		return *s.policies.DownReg.MaxExpTime
	case PropPolicy:
		return *s.policies.Prop.MaxExpTime
	}
	return DefaultMaxExpTime
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
func NewCoreBeaconStore(policies CorePolicies, db DB, opts ...StoreOption) (*CoreStore, error) {
	policies.InitDefaults()
	if err := policies.Validate(); err != nil {
		return nil, err
	}
	o := applyStoreOptions(opts)
	s := &CoreStore{
		baseStore: baseStore{
			db:   db,
			algo: selectAlgo(o),
		},
		policies: policies,
	}
	s.usager = &s.policies
	return s, nil
}

// BeaconsToPropagate returns a slice of all beacons to propagate at the time of the call.
// The selection is based on the configured propagation policy.
func (s *CoreStore) BeaconsToPropagate(ctx context.Context) ([]Beacon, error) {
	return s.getBeacons(ctx, &s.policies.Prop)
}

// SegmentsToRegister returns a slice of all beacons to register at the time of the call.
// The selections is based on the configured policy for the requested segment type.
func (s *CoreStore) SegmentsToRegister(ctx context.Context, segType seg.Type) ([]Beacon, error) {

	if segType != seg.TypeCore {
		return nil, serrors.New("Unsupported segment type", "type", segType)
	}
	return s.getBeacons(ctx, &s.policies.CoreReg)
}

// getBeacons fetches the candidate beacons from the database and serves the
// best beacons according to the policy.
func (s *CoreStore) getBeacons(ctx context.Context, policy *Policy) ([]Beacon, error) {
	srcs, err := s.db.BeaconSources(ctx)
	if err != nil {
		return nil, err
	}
	var beacons []Beacon
	for _, src := range srcs {
		candidateBeacons, err := s.db.CandidateBeacons(ctx, policy.CandidateSetSize,
			UsageFromPolicyType(policy.Type), src)
		// Must not return as a partial result is better than no result at all.
		if err != nil {
			log.FromCtx(ctx).Error("Error getting candidate beacons", "src", src, "err", err)
			continue
		}
		selBeacons := s.algo.SelectBeacons(ctx, candidateBeacons, policy.BestSetSize)
		beacons = append(beacons, selBeacons...)
	}
	return beacons, nil
}

// MaxExpTime returns the segment maximum expiration time for the given policy.
func (s *CoreStore) MaxExpTime(policyType PolicyType) uint8 {
	switch policyType {
	case CoreRegPolicy:
		return *s.policies.CoreReg.MaxExpTime
	case PropPolicy:
		return *s.policies.Prop.MaxExpTime
	}
	return DefaultMaxExpTime
}

// baseStore is the basis for the beacon store.
type baseStore struct {
	db     DB
	usager usager
	algo   selectionAlgorithm
}

// PreFilter indicates whether the beacon will be filtered on insert by
// returning an error with the reason. This allows the caller to drop
// ignored beacons.
func (s *baseStore) PreFilter(beacon Beacon) error {
	return s.usager.Filter(beacon)
}

// InsertBeacon adds a verified beacon to the store.
// Beacon that contains revoked interfaces is inserted and does not cause an error.
// If the beacon does not match any policy, it is not inserted, but does not cause an error.
func (s *baseStore) InsertBeacon(ctx context.Context, beacon Beacon) (InsertStats, error) {
	usage := s.usager.Usage(beacon)
	if usage.None() {
		return InsertStats{Filtered: 1}, nil
	}
	return s.db.InsertBeacon(ctx, beacon, usage)
}

// UpdatePolicy updates the policy. Beacons that are filtered by all
// policies after the update are removed.
func (s *baseStore) UpdatePolicy(ctx context.Context, policy Policy) error {
	return serrors.New("policy update not supported")
}

func selectAlgo(o storeOptions) selectionAlgorithm {
	if o.chainChecker != nil {
		return newChainsAvailableAlgo(o.chainChecker)
	}
	return baseAlgo{}
}
